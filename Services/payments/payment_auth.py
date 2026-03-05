from datetime import timezone
from flask import current_app, flash, redirect, render_template, request, session, url_for
import os

from datetime import datetime, timedelta
import hashlib
import requests
from urllib.parse import quote_plus

from Services.payments.payment_utils import pay_notify_handler

merchant_id = os.getenv('PAYFAST_MERCHANT_ID')
merchant_key = os.getenv('PAYFAST_MERCHANT_KEY')

EXPECTED_PLAN_AMOUNTS = {
    "monthly": "149.00",
    "annual": "1699.00",
}

def payment_op():
    user = session.get('user')
    if not user:
        return redirect(url_for('login'))

    plan = request.args.get('plan', 'monthly')
    if plan not in ('monthly', 'annual'):
        plan = 'monthly'

    recurring = request.args.get('recurring', 'false') == 'true'

    if plan == 'annual':
        item_name = 'Paid Plan - Annual Subscription'
        recurring_amount = '1699.00'
        amount = '1699.00'
        frequency = 6  # 6 = yearly in PayFast
    else:
        item_name = 'Paid Plan - Monthly Subscription'
        recurring_amount = '149.00'
        amount = '149.00'
        frequency = 3  # 3 = monthly in PayFast

    # Generate unique merchant reference for better tracking
    merchant_ref = f"{user.get('email', '')}-{plan}-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"

    notify_base = os.getenv('PAYFAST_NOTIFY_URL') or url_for('pay_notify', _external=True)
    if "/pay/notify" in notify_base:
        notify_url = notify_base
    else:
        notify_url = notify_base.rstrip("/") + "/pay/notify"
    
    payfast_data = {
            'merchant_id': merchant_id,
        'merchant_key': merchant_key,
        'amount': amount,
        'item_name': item_name,
        'name_first': user.get('name', ''),
        'email_address': user.get('email', ''),
        'return_url': url_for('pay_success', plan=plan, _external=True),
        'cancel_url': url_for('pay_cancel', _external=True),
        'notify_url': notify_url,
        'custom_str1': user.get('email', ''),
        'custom_str2': plan,
        'custom_str3': merchant_ref,
        'm_payment_id': merchant_ref
    }

    if recurring:
        billing_date = (datetime.now(timezone.utc) + timedelta(days=1)).strftime('%Y-%m-%d')
        payfast_data.update({
            'subscription_type': 1,
            'billing_date': billing_date,
            'recurring_amount': recurring_amount,
            'frequency': frequency,
            'cycles': 0
        })
        
        current_app.logger.info(f"Creating recurring subscription for {user.get('email', '')}: {payfast_data}")
        print(f"Recurring subscription data: {payfast_data}")  # Terminal log

    return render_template(
    'payfast_form.html',
    payfast=payfast_data,
    recurring=recurring,
    is_sandbox=os.getenv('PAYFAST_SANDBOX', 'true').lower() == 'true'
)

def payment_successful(users_collection):
    user = session.get('user')
    if not user:
        return redirect(url_for('login'))
    
    flash('Payment received! Your account will be upgraded shortly.', 'info')



    frontend_url = os.getenv('FRONTEND_URL', 'http://localhost:3000')
    return redirect(f"{frontend_url}/mentormate-homepage")


def payment_notification(users_collection, PAYFAST_SANDBOX, PAYFAST_PASSPHRASE):
    print("--- PayFast ITN Received ---")
    current_app.logger.info("--- PayFast ITN Received ---")

    # Read raw body FIRST before anything touches request.form
    raw_body_bytes = request.get_data()
    raw_body = raw_body_bytes.decode('utf-8')
    print(f"Raw ITN Body: {raw_body}")
    current_app.logger.info(f"Raw ITN Body: {raw_body}")

    received_signature = request.form.get('signature')
    print(f"Received Signature: {received_signature}")
    current_app.logger.info(f"Received Signature: {received_signature}")

    if not received_signature:
        current_app.logger.error("No signature field found in ITN data")
        return "Invalid request", 400

    # Parse fields preserving order, skip signature
    from urllib.parse import parse_qsl
    pairs = parse_qsl(raw_body, keep_blank_values=True)
    pairs_no_sig = [(k, v) for k, v in pairs if k != 'signature']

    # Rebuild string using quote_plus (same as PHP urlencode)
    parts = [f'{k}={quote_plus(v)}' for k, v in pairs_no_sig]
    payload_to_hash = '&'.join(parts)

    # ALWAYS append passphrase if one is set (applies to both sandbox AND production)
    if PAYFAST_PASSPHRASE:
        string_to_check = f"{payload_to_hash}&passphrase={quote_plus(PAYFAST_PASSPHRASE)}"
    else:
        string_to_check = payload_to_hash

    print(f"Final String for Hashing: {string_to_check}")
    current_app.logger.info(f"Final String for Hashing: {string_to_check}")

    calculated_signature = hashlib.md5(string_to_check.encode('utf-8')).hexdigest()

    print(f"Calculated Signature: {calculated_signature}")
    current_app.logger.info(f"Calculated Signature: {calculated_signature}")

    if calculated_signature != received_signature:
        print("!!! SIGNATURE MISMATCH !!!")
        current_app.logger.error("!!! PayFast ITN Signature Mismatch !!!")
        return "Invalid signature", 400

    print("--- SIGNATURE VERIFIED ---")
    current_app.logger.info("--- PayFast ITN Signature Verified ---")

    # Server-to-server ITN validation with PayFast 
    validation_url = (
        "https://sandbox.payfast.co.za/eng/query/validate"
        if PAYFAST_SANDBOX
        else "https://www.payfast.co.za/eng/query/validate"
    )

    try:
        validation_response = requests.post(
            validation_url,
            data=request.form,
            timeout=10,
        )
    except requests.RequestException as exc:
        current_app.logger.error(f"Error validating ITN with PayFast: {exc}")
        return "Error validating ITN", 502

    if (
        validation_response.status_code != 200
        or "VALID" not in validation_response.text.upper()
    ):
        current_app.logger.error(
            f"PayFast ITN validation failed: status={validation_response.status_code}, "
            f"body={validation_response.text!r}"
        )
        return "ITN validation failed", 400

    current_app.logger.info("PayFast ITN validation confirmed as VALID")

    data = request.form.to_dict(flat=True)

    itn_merchant_id = data.get("merchant_id")
    if itn_merchant_id != merchant_id:
        current_app.logger.error(
            f"ITN merchant_id mismatch: got {itn_merchant_id}, expected {merchant_id}"
        )
        return "Invalid merchant", 400

    plan = data.get("custom_str2", "monthly")
    expected_amount = EXPECTED_PLAN_AMOUNTS.get(plan, EXPECTED_PLAN_AMOUNTS["monthly"])
    itn_amount = data.get("amount_gross") or data.get("amount")
    if itn_amount != expected_amount:
        current_app.logger.error(
            f"ITN amount mismatch for plan {plan}: got {itn_amount}, expected {expected_amount}"
        )
        return "Invalid amount", 400

    result = pay_notify_handler(data, users_collection)

    if not result.get('success'):
        current_app.logger.warning(
            f"ITN processing did not complete successfully: {result}"
        )

    return 'OK', 200