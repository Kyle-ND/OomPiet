from datetime import datetime,timedelta, timezone

from flask import current_app

FREE_TIER_LIMIT = 5          # messages per reset period
RESET_PERIOD_DAYS = 30       # days before quota resets after depletion

def _canonical_email(email: str) -> str:
    """Normalise email to lowercase and strip whitespace."""
    return email.strip().lower()


def _get_quota_doc(users_collection, email: str) -> dict | None:
    """Fetch the user document from the DB by email."""
    return users_collection.find_one({"email": email})

def get_limit_status(users_collection, email: str) -> dict:
    email = _canonical_email(email)
    user = _get_quota_doc(users_collection, email)

    if not user:
        return {"can_query": False, "reason": "User not found", "is_premium": False}

    if user.get("premium", False):
        return {
            "is_premium": True,
            "free_messages_used": 0,
            "free_messages_remaining": FREE_TIER_LIMIT,
            "limit": FREE_TIER_LIMIT,
            "quota_depleted_at": None,
            "quota_resets_at": None,
            "can_query": True,
            "reason": "Paid Plan user – unlimited queries"
        }

    used = user.get("free_messages_used", 0)
    depleted_at = user.get("quota_depleted_at")
    resets_at = None

    if depleted_at is not None:
        if depleted_at.tzinfo is None:
            depleted_at = depleted_at.replace(tzinfo=timezone.utc)
        resets_at = depleted_at + timedelta(days=RESET_PERIOD_DAYS)
        now = datetime.now(timezone.utc)

        if now >= resets_at:
            users_collection.update_one(
                {"email": email},
                {"$set": {
                    "free_messages_used": 0,
                    "quota_depleted_at": None,
                    "quota_reset_at": now
                }}
            )
            used = 0
            depleted_at = None
            resets_at = None

    # If not depleted yet but user has started using messages,
    # estimate reset date based on first_message_at or fallback to 30 days from now
    if resets_at is None and used > 0:
        first_message_at = user.get("first_message_at")
        depleted_at_raw = user.get("quota_depleted_at")
        if first_message_at:
            if first_message_at.tzinfo is None:
                first_message_at = first_message_at.replace(tzinfo=timezone.utc)
            resets_at = first_message_at + timedelta(days=RESET_PERIOD_DAYS)
        elif depleted_at_raw:
            if depleted_at_raw.tzinfo is None:
                depleted_at_raw = depleted_at_raw.replace(tzinfo=timezone.utc)
            resets_at = depleted_at_raw + timedelta(days=RESET_PERIOD_DAYS)
        else:
            # 30 days from now
            resets_at = datetime.now(timezone.utc) + timedelta(days=RESET_PERIOD_DAYS)


    remaining = max(0, FREE_TIER_LIMIT - used)
    can_query = remaining > 0

    return {
        "is_premium": False,
        "free_messages_used": used,
        "free_messages_remaining": remaining,
        "limit": FREE_TIER_LIMIT,
        "quota_depleted_at": depleted_at,
        "quota_resets_at": resets_at, 
        "can_query": can_query,
        "reason": (
            "Free tier active"
            if can_query
            else f"Free tier exhausted. Resets on {resets_at.strftime('%Y-%m-%d') if resets_at else 'N/A'}"
        )
    }

def consume_free_message(users_collection, email: str) -> dict:
    email = _canonical_email(email)
    now = datetime.now(timezone.utc)

    result = users_collection.update_one(
        {
            "email": email,
            "premium": {"$ne": True},
            "$or": [
                {"free_messages_used": {"$exists": False}},
                {"free_messages_used": {"$lt": FREE_TIER_LIMIT}}
            ]
        },
        {
            "$inc": {"free_messages_used": 1},
            # Only set first_message_at if it doesn't exist yet
            "$setOnInsert": {},
        }
    )

    # Set first_message_at only on first message
    users_collection.update_one(
        {"email": email, "first_message_at": {"$exists": False}},
        {"$set": {"first_message_at": now}}
    )

    if result.modified_count == 0:
        current_app.logger.warning(
            f"consume_free_message: no update for {email} – already at limit or premium"
        )

    user = _get_quota_doc(users_collection, email)
    used = user.get("free_messages_used", 0) if user else FREE_TIER_LIMIT

    if used >= FREE_TIER_LIMIT and not user.get("quota_depleted_at"):
        users_collection.update_one(
            {"email": email, "quota_depleted_at": {"$exists": False}},
            {"$set": {"quota_depleted_at": now}}
        )

    return get_limit_status(users_collection, email)


def pay_notify_handler(data, users_collection):
    """Helper function to process PayFast ITN data (called from payment_auth)."""
    payment_status = data.get('payment_status')
    email = _canonical_email(data.get('custom_str1', ''))
    plan = data.get('custom_str2', 'monthly')

     # Validate plan is known 
    if plan not in ('monthly', 'annual'):
        current_app.logger.warning(
            f"Unknown plan '{plan}' in ITN – defaulting to monthly"
        )
        plan = 'monthly'


    if payment_status == 'COMPLETE' and email:
        pf_subscription_id = (
            data.get('pf_subscription_id') or
            data.get('subscription_id') or
            data.get('recurring_transaction_id') or
            data.get('m_payment_id') or
            ''
        )

        current_app.logger.info(
            f"Processing payment for {email}, subscription_id: {pf_subscription_id}"
        )

        if plan == 'annual':
            subscription_end = datetime.now(timezone.utc) + timedelta(days=365)
        else:
            subscription_end = datetime.now(timezone.utc) + timedelta(days=30)

        update_fields = {
            'premium': True,
            'subscription_plan': plan,
            'subscription_start': datetime.now(timezone.utc),
            'subscription_end': subscription_end,
            'payment_amount': data.get('amount_gross') or data.get('amount', '0.00'),
            'payment_id': data.get('pf_payment_id', ''),
            'last_payment_date': datetime.now(timezone.utc),
            'free_messages_used': 0,
            'quota_depleted_at': None,
        }

        if pf_subscription_id:
            update_fields['payfast_subscription_id'] = pf_subscription_id
            current_app.logger.info(f"Subscription ID captured: {pf_subscription_id}")
        else:
            current_app.logger.warning(
                f"No subscription ID found in ITN data for {email}"
            )

        users_collection.update_one({'email': email}, {'$set': update_fields})

        return {'success': True, 'subscription_id': pf_subscription_id}

    return {'success': False, 'error': 'Invalid payment status or missing email'}
