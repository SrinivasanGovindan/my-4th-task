from collections import defaultdict
from datetime import datetime
from typing import List

import graphene
import pytz

from .....core.tracing import traced_atomic_transaction
from .....discount import models
from .....discount.sale_converter import create_catalogue_predicate
from .....discount.utils import CATALOGUE_FIELDS, fetch_catalogue_info
from .....permission.enums import DiscountPermissions
from .....product.tasks import update_products_discounted_prices_of_catalogues_task
from .....webhook.event_types import WebhookEventAsyncType
from ....channel import ChannelContext
from ....core import ResolveInfo
from ....core.descriptions import DEPRECATED_IN_3X_MUTATION
from ....core.doc_category import DOC_CATEGORY_DISCOUNTS
from ....core.mutations import ModelMutation
from ....core.types import DiscountError
from ....core.utils import WebhookEventInfo
from ....plugins.dataloaders import get_plugin_manager_promise
from ...types import Sale
from ...utils import convert_migrated_sale_predicate_to_catalogue_info
from ..utils import convert_catalogue_info_to_global_ids
from .sale_create import SaleInput


class SaleUpdate(ModelMutation):
    class Arguments:
        id = graphene.ID(required=True, description="ID of a sale to update.")
        input = SaleInput(
            required=True, description="Fields required to update a sale."
        )

    class Meta:
        description = (
            "Updates a sale."
            + DEPRECATED_IN_3X_MUTATION
            + " Use `promotionUpdate` mutation instead."
        )
        model = models.Promotion
        object_type = Sale
        return_field_name = "sale"
        permissions = (DiscountPermissions.MANAGE_DISCOUNTS,)
        error_type_class = DiscountError
        error_type_field = "discount_errors"
        doc_category = DOC_CATEGORY_DISCOUNTS
        webhook_events_info = [
            WebhookEventInfo(
                type=WebhookEventAsyncType.SALE_UPDATED,
                description="A sale was updated.",
            ),
            WebhookEventInfo(
                type=WebhookEventAsyncType.SALE_TOGGLE,
                description="Optionally triggered when a sale is started or stopped.",
            ),
        ]

    @classmethod
    def perform_mutation(cls, _root, info: ResolveInfo, /, **data):
        promotion = cls.get_instance(info, **data)
        rules = promotion.rules.all()
        predicate = rules[0].catalogue_predicate
        previous_catalogue = convert_migrated_sale_predicate_to_catalogue_info(
            predicate
        )
        previous_end_date = promotion.end_date
        manager = get_plugin_manager_promise(info.context).get()
        with traced_atomic_transaction():
            input = data.get("input")
            cls.update_fields(promotion, rules, input)

            cls.clean_instance(info, promotion)
            promotion.save()
            for rule in rules:
                cls.clean_instance(info, rule)
                rule.save()
            # current_catalogue = fetch_catalogue_info(instance)
            # cls.send_sale_notifications(
            #     manager,
            #     instance,
            #     cleaned_input,
            #     previous_catalogue,
            #     current_catalogue,
            #     previous_end_date,
            # )
            #
            # cls.update_products_discounted_prices(
            #     cleaned_input, previous_catalogue, current_catalogue
            # )
        return cls.success_response(ChannelContext(node=promotion, channel_slug=None))

    # TODO no date validation???
    # TODO what is "value" in input for???
    # TODO check where None can be passed

    @classmethod
    def get_instance(cls, info: ResolveInfo, **data):
        object_id = cls.get_global_id_or_error(data["id"], "Sale")
        return models.Promotion.objects.get(old_sale_id=object_id)

    @classmethod
    def update_fields(
        cls, promotion: models.Promotion, rules: List[models.PromotionRule], input
    ):
        if name := input.get("name"):
            promotion.name = name
        if start_date := input.get("start_date"):
            promotion.start_date = start_date
        if end_date := input.get("end_date"):
            promotion.end_date = end_date

        # We need to make sure, that all rules have the same type and predicate
        if type := input.get("type"):
            for rule in rules:
                rule.reward_value_type = type
        fields = ["collections", "categories", "products", "variants"]
        if any([key in fields for key in input.keys()]):
            predicate = cls.create_predicate(input)
            for rule in rules:
                rule.catalogue_predicate = predicate

    @staticmethod
    def create_predicate(input):
        collections = input.get("collections")
        categories = input.get("categories")
        products = input.get("products")
        variants = input.get("variants")

        return create_catalogue_predicate(collections, categories, products, variants)

    @classmethod
    def send_sale_notifications(
        cls,
        manager,
        instance,
        cleaned_input,
        previous_catalogue,
        current_catalogue,
        previous_end_date,
    ):
        current_catalogue = convert_catalogue_info_to_global_ids(current_catalogue)
        cls.call_event(
            manager.sale_updated,
            instance,
            convert_catalogue_info_to_global_ids(previous_catalogue),
            current_catalogue,
        )

        cls.send_sale_toggle_notification(
            manager, instance, cleaned_input, current_catalogue, previous_end_date
        )

    @staticmethod
    def send_sale_toggle_notification(
        manager, instance, clean_input, catalogue, previous_end_date
    ):
        """Send the notification about starting or ending sale if it wasn't sent yet.

        Send notification if the notification when the start or end date already passed
        and the notification_date is not set or the last notification was sent
        before start or end date.
        """
        now = datetime.now(pytz.utc)

        notification_date = instance.notification_sent_datetime
        start_date = clean_input.get("start_date")
        end_date = clean_input.get("end_date")

        if not start_date and not end_date:
            return

        send_notification = False
        for date in [start_date, end_date]:
            if (
                date
                and date <= now
                and (notification_date is None or notification_date < date)
            ):
                send_notification = True

        # we always need to notify if the end_date is in the past and previously
        # the end date was not set
        if end_date and end_date <= now and previous_end_date is None:
            send_notification = True

        if send_notification:
            manager.sale_toggle(instance, catalogue)
            instance.notification_sent_datetime = now
            instance.save(update_fields=["notification_sent_datetime"])

    @staticmethod
    def update_products_discounted_prices(
        cleaned_input, previous_catalogue, current_catalogue
    ):
        catalogues_to_recalculate = defaultdict(set)
        for catalogue_field in CATALOGUE_FIELDS:
            if any(
                [
                    field in cleaned_input
                    for field in [
                        catalogue_field,
                        "start_date",
                        "end_date",
                        "type",
                        "value",
                    ]
                ]
            ):
                catalogues_to_recalculate[catalogue_field] = previous_catalogue[
                    catalogue_field
                ].union(current_catalogue[catalogue_field])

        if catalogues_to_recalculate:
            update_products_discounted_prices_of_catalogues_task.delay(
                product_ids=list(catalogues_to_recalculate["products"]),
                category_ids=list(catalogues_to_recalculate["categories"]),
                collection_ids=list(catalogues_to_recalculate["collections"]),
                variant_ids=list(catalogues_to_recalculate["variants"]),
            )
