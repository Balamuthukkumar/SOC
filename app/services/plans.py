PLANS = {
    "free": {"max_assets": 10, "max_users": 1, "price_monthly": 0, "features": ["basic_alerts"]},
    "starter": {"max_assets": 100, "max_users": 5, "price_monthly": 49900, "features": ["basic_alerts", "epss", "slack_integration"]},
    "pro": {"max_assets": 500, "max_users": 20, "price_monthly": 199900,
            "features": ["basic_alerts", "epss", "slack_integration", "compliance", "sbom", "topology"]},
    "enterprise": {"max_assets": 99999, "max_users": 99999, "price_monthly": 499900, "features": ["all"]},
}


def plan_info(name: str) -> dict:
    return {"plan": name, **PLANS[name]}
