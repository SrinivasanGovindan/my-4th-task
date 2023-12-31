# Generated by Django 3.2.19 on 2023-06-01 08:15

from django.apps import apps as registry
from django.db import migrations, models
from django.db.models.signals import post_migrate

from .tasks.saleor3_15 import drop_status_field_from_transaction_event_task


def drop_status_field_from_transaction_event(apps, _schema_editor):
    def on_migrations_complete(sender=None, **kwargs):
        drop_status_field_from_transaction_event_task.delay()

    sender = registry.get_app_config("order")
    post_migrate.connect(on_migrations_complete, weak=False, sender=sender)


class Migration(migrations.Migration):
    dependencies = [
        ("order", "0171_auto_20230518_0854"),
    ]

    operations = [
        migrations.AlterField(
            model_name="orderevent",
            name="type",
            field=models.CharField(
                choices=[
                    ("DRAFT_CREATED", "draft_created"),
                    ("DRAFT_CREATED_FROM_REPLACE", "draft_created_from_replace"),
                    ("ADDED_PRODUCTS", "added_products"),
                    ("REMOVED_PRODUCTS", "removed_products"),
                    ("PLACED", "placed"),
                    ("PLACED_FROM_DRAFT", "placed_from_draft"),
                    ("OVERSOLD_ITEMS", "oversold_items"),
                    ("CANCELED", "canceled"),
                    ("EXPIRED", "expired"),
                    ("ORDER_MARKED_AS_PAID", "order_marked_as_paid"),
                    ("ORDER_FULLY_PAID", "order_fully_paid"),
                    ("ORDER_REPLACEMENT_CREATED", "order_replacement_created"),
                    ("ORDER_DISCOUNT_ADDED", "order_discount_added"),
                    (
                        "ORDER_DISCOUNT_AUTOMATICALLY_UPDATED",
                        "order_discount_automatically_updated",
                    ),
                    ("ORDER_DISCOUNT_UPDATED", "order_discount_updated"),
                    ("ORDER_DISCOUNT_DELETED", "order_discount_deleted"),
                    ("ORDER_LINE_DISCOUNT_UPDATED", "order_line_discount_updated"),
                    ("ORDER_LINE_DISCOUNT_REMOVED", "order_line_discount_removed"),
                    ("ORDER_LINE_PRODUCT_DELETED", "order_line_product_deleted"),
                    ("ORDER_LINE_VARIANT_DELETED", "order_line_variant_deleted"),
                    ("UPDATED_ADDRESS", "updated_address"),
                    ("EMAIL_SENT", "email_sent"),
                    ("CONFIRMED", "confirmed"),
                    ("PAYMENT_AUTHORIZED", "payment_authorized"),
                    ("PAYMENT_CAPTURED", "payment_captured"),
                    ("EXTERNAL_SERVICE_NOTIFICATION", "external_service_notification"),
                    ("PAYMENT_REFUNDED", "payment_refunded"),
                    ("PAYMENT_VOIDED", "payment_voided"),
                    ("PAYMENT_FAILED", "payment_failed"),
                    ("TRANSACTION_EVENT", "transaction_event"),
                    ("TRANSACTION_CHARGE_REQUESTED", "transaction_charge_requested"),
                    ("TRANSACTION_REFUND_REQUESTED", "transaction_refund_requested"),
                    ("TRANSACTION_CANCEL_REQUESTED", "transaction_cancel_requested"),
                    (
                        "TRANSACTION_MARK_AS_PAID_FAILED",
                        "transaction_mark_as_paid_failed",
                    ),
                    ("INVOICE_REQUESTED", "invoice_requested"),
                    ("INVOICE_GENERATED", "invoice_generated"),
                    ("INVOICE_UPDATED", "invoice_updated"),
                    ("INVOICE_SENT", "invoice_sent"),
                    ("FULFILLMENT_CANCELED", "fulfillment_canceled"),
                    ("FULFILLMENT_RESTOCKED_ITEMS", "fulfillment_restocked_items"),
                    ("FULFILLMENT_FULFILLED_ITEMS", "fulfillment_fulfilled_items"),
                    ("FULFILLMENT_REFUNDED", "fulfillment_refunded"),
                    ("FULFILLMENT_RETURNED", "fulfillment_returned"),
                    ("FULFILLMENT_REPLACED", "fulfillment_replaced"),
                    ("FULFILLMENT_AWAITS_APPROVAL", "fulfillment_awaits_approval"),
                    ("TRACKING_UPDATED", "tracking_updated"),
                    ("NOTE_ADDED", "note_added"),
                    ("NOTE_UPDATED", "note_updated"),
                    ("OTHER", "other"),
                ],
                max_length=255,
            ),
        ),
        migrations.RunPython(
            drop_status_field_from_transaction_event,
            reverse_code=migrations.RunPython.noop,
        ),
    ]
