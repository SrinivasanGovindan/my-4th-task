from ....core.permissions import DiscountPermissions
from ...core.types import DiscountError
from ..types import Voucher
from .voucher_add_catalogues import VoucherBaseCatalogueMutation


class VoucherRemoveCatalogues(VoucherBaseCatalogueMutation):
    class Meta:
        description = "Removes products, categories, collections from a voucher."
        permissions = (DiscountPermissions.MANAGE_DISCOUNTS,)
        error_type_class = DiscountError
        error_type_field = "discount_errors"

    @classmethod
    def perform_mutation(cls, _root, info, **data):
        voucher = cls.get_node_or_error(
            info, data.get("id"), only_type=Voucher, field="voucher_id"
        )
        input_data = data.get("input", {})
        cls.remove_catalogues_from_node(voucher, input_data)

        if input_data:
            info.context.plugins.voucher_updated(voucher)

        return VoucherRemoveCatalogues(voucher=voucher)