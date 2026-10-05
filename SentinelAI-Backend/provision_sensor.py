"""Provision a site and issue one high-entropy sensor Bearer token.

Run from SentinelAI-Backend after setting DATABASE_URL. The token is shown once;
only its SHA-256 digest is stored in PostgreSQL.
"""

from __future__ import annotations

import argparse
import hashlib
import math
import secrets
from pathlib import Path

from dotenv import load_dotenv
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError


load_dotenv(Path(__file__).resolve().parent / ".env")

try:
    from .database import SessionLocal, create_database_tables
    from .models import Sensor, Site, SiteConfig
except ImportError:  # Also works as ``python provision_sensor.py``.
    from database import SessionLocal, create_database_tables
    from models import Sensor, Site, SiteConfig


def positive_threshold(value: str) -> float:
    threshold = float(value)
    if not math.isfinite(threshold) or threshold <= 0:
        raise argparse.ArgumentTypeError("threshold must be a positive finite MSE")
    return threshold


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--site-slug", required=True, help="stable unique site identifier")
    parser.add_argument("--site-name", required=True, help="display name for a new site")
    parser.add_argument("--sensor-name", required=True, help="unique sensor name within the site")
    parser.add_argument("--threshold", type=positive_threshold, help="site MSE threshold")
    response = parser.add_mutually_exclusive_group()
    response.add_argument("--active-response", action="store_true", dest="active_response")
    response.add_argument("--disable-active-response", action="store_false", dest="active_response")
    parser.set_defaults(active_response=None)
    return parser


def provision_sensor(args: argparse.Namespace) -> str:
    """Create the sensor transactionally and return its plaintext token once."""

    slug = args.site_slug.strip()
    site_name = args.site_name.strip()
    sensor_name = args.sensor_name.strip()
    if not slug or not site_name or not sensor_name:
        raise ValueError("site slug, site name, and sensor name cannot be blank")

    token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    create_database_tables()
    with SessionLocal.begin() as db:
        site = db.scalar(select(Site).where(Site.slug == slug))
        if site is None:
            site = Site(slug=slug, name=site_name, is_active=True)
            db.add(site)
            db.flush()
        elif not site.is_active:
            raise ValueError(f"site {slug!r} is inactive")

        config = db.get(SiteConfig, site.id)
        if config is None:
            config = SiteConfig(
                site_id=site.id,
                custom_mse_threshold=args.threshold,
                active_response_enabled=bool(args.active_response),
            )
            db.add(config)
        else:
            if args.threshold is not None:
                config.custom_mse_threshold = args.threshold
            if args.active_response is not None:
                config.active_response_enabled = args.active_response

        existing = db.scalar(
            select(Sensor).where(Sensor.site_id == site.id, Sensor.name == sensor_name)
        )
        if existing is not None:
            raise ValueError(f"sensor {sensor_name!r} already exists at site {slug!r}")
        db.add(
            Sensor(
                site_id=site.id,
                name=sensor_name,
                token_hash=token_hash,
                is_active=True,
            )
        )
    return token


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        token = provision_sensor(args)
    except (IntegrityError, ValueError) as exc:
        print(f"Provisioning failed: {exc}")
        return 1
    print("Sensor created. Save this token now; it cannot be retrieved from the database.")
    print(f"SENTINEL_SENSOR_TOKEN={token}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
