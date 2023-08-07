import graphene

from .....core.tracing import traced_atomic_transaction
from .....discount import models
from .....graphql.core.mutations import ModelDeleteMutation
from .....permission.enums import DiscountPermissions
from .....product.tasks import update_products_discounted_prices_for_promotion_task
from .....webhook.event_types import WebhookEventAsyncType
from ....channel import ChannelContext
from ....core import ResolveInfo
from ....core.descriptions import DEPRECATED_IN_3X_MUTATION
from ....core.doc_category import DOC_CATEGORY_DISCOUNTS
from ....core.types import DiscountError
from ....core.utils import WebhookEventInfo
from ....plugins.dataloaders import get_plugin_manager_promise
from ...types import Sale
from ...utils import (
    convert_migrated_sale_predicate_to_catalogue_info,
    get_products_for_rule,
)


class SaleDelete(ModelDeleteMutation):
    class Arguments:
        id = graphene.ID(required=True, description="ID of a sale to delete.")

    class Meta:
        description = (
            "Deletes a sale."
            + DEPRECATED_IN_3X_MUTATION
            + " Use `promotionDelete` mutation instead."
        )
        model = models.Promotion
        object_type = Sale
        return_field_name = "sale"
        doc_category = DOC_CATEGORY_DISCOUNTS
        permissions = (DiscountPermissions.MANAGE_DISCOUNTS,)
        error_type_class = DiscountError
        error_type_field = "discount_errors"
        webhook_events_info = [
            WebhookEventInfo(
                type=WebhookEventAsyncType.SALE_DELETED,
                description="A sale was deleted.",
            ),
        ]

    @classmethod
    def perform_mutation(  # type: ignore[override]
        cls, root, info: ResolveInfo, /, *, id: str
    ):
        object_id = cls.get_global_id_or_error(id, "Sale")
        promotion = models.Promotion.objects.get(old_sale_id=object_id)
        promotion_id = promotion.id
        rules = promotion.rules.all()
        previous_predicate = rules[0].catalogue_predicate
        previous_catalogue = convert_migrated_sale_predicate_to_catalogue_info(
            previous_predicate
        )
        products = get_products_for_rule(rules[0])
        product_ids = set(products.values_list("id", flat=True))
        with traced_atomic_transaction():
            promotion.delete()
            promotion.old_sale_id = object_id
            promotion.id = promotion_id
            response = cls.success_response(promotion)
            response.sale = ChannelContext(node=promotion, channel_slug=None)

            manager = get_plugin_manager_promise(info.context).get()
            cls.call_event(manager.sale_deleted, promotion, previous_catalogue)
            update_products_discounted_prices_for_promotion_task.delay(
                list(product_ids)
            )

        return response
