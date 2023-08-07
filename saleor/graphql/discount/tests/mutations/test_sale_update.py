from datetime import timedelta
from unittest.mock import patch

import graphene
from django.utils import timezone
from freezegun import freeze_time

from .....discount import DiscountValueType
from .....discount.error_codes import DiscountErrorCode
from .....discount.models import Promotion
from .....discount.sale_converter import convert_sales_to_promotions
from .....discount.utils import fetch_catalogue_info
from ....tests.utils import get_graphql_content
from ...enums import DiscountValueTypeEnum
from ...mutations.utils import convert_catalogue_info_to_global_ids
from ...utils import convert_migrated_sale_predicate_to_catalogue_info

SALE_UPDATE_MUTATION = """
    mutation  saleUpdate($id: ID!, $input: SaleInput!) {
        saleUpdate(id: $id, input: $input) {
            errors {
                field
                code
                message
            }
            sale {
                name
                type
                startDate
                endDate
            }
        }
    }
"""


@patch(
    "saleor.product.tasks.update_products_discounted_prices_for_promotion_task.delay"
)
@patch("saleor.plugins.manager.PluginsManager.sale_updated")
def test_update_sale(
    updated_webhook_mock,
    update_products_discounted_prices_for_promotion_task_mock,
    staff_api_client,
    sale,
    permission_manage_discounts,
    product_list,
):
    # given
    query = SALE_UPDATE_MUTATION

    # Set discount value type to 'fixed' and change it in mutation
    sale.type = DiscountValueType.FIXED
    sale.save(update_fields=["type"])

    previous_catalogue = convert_catalogue_info_to_global_ids(
        fetch_catalogue_info(sale)
    )
    new_product_pks = [product.id for product in product_list]
    new_product_ids = [
        graphene.Node.to_global_id("Product", product_id)
        for product_id in new_product_pks
    ]

    convert_sales_to_promotions()

    variables = {
        "id": graphene.Node.to_global_id("Sale", sale.id),
        "input": {
            "type": DiscountValueTypeEnum.PERCENTAGE.name,
            "products": new_product_ids,
        },
    }

    # when
    response = staff_api_client.post_graphql(
        query, variables, permissions=[permission_manage_discounts]
    )

    # then
    content = get_graphql_content(response)
    assert not content["data"]["saleUpdate"]["errors"]
    data = content["data"]["saleUpdate"]["sale"]
    assert data["type"] == DiscountValueType.PERCENTAGE.upper()
    promotion = Promotion.objects.get(old_sale_id=sale.id)
    rule = promotion.rules.first()
    assert rule.reward_value_type == DiscountValueType.PERCENTAGE

    current_catalogue = convert_migrated_sale_predicate_to_catalogue_info(
        rule.catalogue_predicate
    )
    updated_webhook_mock.assert_called_once_with(
        promotion, previous_catalogue, current_catalogue
    )
    update_products_discounted_prices_for_promotion_task_mock.assert_called_once()


@patch(
    "saleor.product.tasks.update_products_discounted_prices_for_promotion_task.delay"
)
@patch("saleor.plugins.manager.PluginsManager.sale_updated")
def test_update_sale_name(
    updated_webhook_mock,
    update_products_discounted_prices_for_promotion_task_mock,
    staff_api_client,
    sale,
    permission_manage_discounts,
    product_list,
):
    # given
    query = SALE_UPDATE_MUTATION

    new_name = "New name"
    previous_catalogue = convert_catalogue_info_to_global_ids(
        fetch_catalogue_info(sale)
    )
    convert_sales_to_promotions()
    variables = {
        "id": graphene.Node.to_global_id("Sale", sale.id),
        "input": {
            "name": new_name,
        },
    }

    # when
    response = staff_api_client.post_graphql(
        query, variables, permissions=[permission_manage_discounts]
    )

    # then
    content = get_graphql_content(response)
    assert not content["data"]["saleUpdate"]["errors"]
    data = content["data"]["saleUpdate"]["sale"]
    assert data["name"] == new_name
    promotion = Promotion.objects.get(old_sale_id=sale.id)
    assert promotion.name == new_name

    current_catalogue = convert_migrated_sale_predicate_to_catalogue_info(
        promotion.rules.first().catalogue_predicate
    )
    updated_webhook_mock.assert_called_once_with(
        promotion, previous_catalogue, current_catalogue
    )
    update_products_discounted_prices_for_promotion_task_mock.assert_not_called()


@freeze_time("2020-03-18 12:00:00")
@patch(
    "saleor.product.tasks.update_products_discounted_prices_for_promotion_task.delay"
)
@patch("saleor.plugins.manager.PluginsManager.sale_toggle")
@patch("saleor.plugins.manager.PluginsManager.sale_updated")
def test_update_sale_start_date_after_current_date_notification_not_sent(
    updated_webhook_mock,
    sale_toggle_mock,
    update_products_discounted_prices_for_promotion_task_mock,
    staff_api_client,
    sale,
    permission_manage_discounts,
):
    """Ensure the notification is not sent when the start date is set after the current
    date.
    """
    # given
    query = SALE_UPDATE_MUTATION

    sale.notification_sent_datetime = None
    sale.save(update_fields=["notification_sent_datetime"])
    previous_catalogue = convert_catalogue_info_to_global_ids(
        fetch_catalogue_info(sale)
    )
    start_date = timezone.now() + timedelta(days=1)
    convert_sales_to_promotions()

    variables = {
        "id": graphene.Node.to_global_id("Sale", sale.id),
        "input": {"startDate": start_date},
    }

    # when
    response = staff_api_client.post_graphql(
        query, variables, permissions=[permission_manage_discounts]
    )

    # then
    content = get_graphql_content(response)
    assert not content["data"]["saleUpdate"]["errors"]
    data = content["data"]["saleUpdate"]["sale"]
    assert data["startDate"] == start_date.isoformat()
    promotion = Promotion.objects.get(old_sale_id=sale.id)
    assert promotion.start_date.isoformat() == start_date.isoformat()
    assert promotion.last_notification_scheduled_at is None

    current_catalogue = convert_migrated_sale_predicate_to_catalogue_info(
        promotion.rules.first().catalogue_predicate
    )
    updated_webhook_mock.assert_called_once_with(
        promotion, previous_catalogue, current_catalogue
    )
    sale_toggle_mock.assert_not_called()
    update_products_discounted_prices_for_promotion_task_mock.assert_called_once()


@freeze_time("2020-03-18 12:00:00")
@patch(
    "saleor.product.tasks.update_products_discounted_prices_for_promotion_task.delay"
)
@patch("saleor.plugins.manager.PluginsManager.sale_toggle")
@patch("saleor.plugins.manager.PluginsManager.sale_updated")
def test_update_sale_start_date_before_current_date_notification_already_sent(
    updated_webhook_mock,
    sale_toggle_mock,
    update_products_discounted_prices_for_promotion_task_mock,
    staff_api_client,
    sale,
    permission_manage_discounts,
):
    """Ensure the notification is not sent when the start date is set before
    current date and notification was already sent.
    """
    # given
    query = SALE_UPDATE_MUTATION
    now = timezone.now()

    # Set discount value type to 'fixed' and change it in mutation
    sale.type = DiscountValueType.FIXED
    notification_sent_datetime = now - timedelta(minutes=5)
    sale.notification_sent_datetime = notification_sent_datetime
    sale.save(update_fields=["type", "notification_sent_datetime"])
    previous_catalogue = convert_catalogue_info_to_global_ids(
        fetch_catalogue_info(sale)
    )
    start_date = timezone.now() - timedelta(days=1)
    convert_sales_to_promotions()

    variables = {
        "id": graphene.Node.to_global_id("Sale", sale.id),
        "input": {"startDate": start_date},
    }

    # when
    response = staff_api_client.post_graphql(
        query, variables, permissions=[permission_manage_discounts]
    )

    # then
    content = get_graphql_content(response)
    assert not content["data"]["saleUpdate"]["errors"]
    data = content["data"]["saleUpdate"]["sale"]
    assert data["startDate"] == start_date.isoformat()
    promotion = Promotion.objects.get(old_sale_id=sale.id)
    assert promotion.start_date.isoformat() == start_date.isoformat()
    assert (
        promotion.last_notification_scheduled_at.isoformat()
        == notification_sent_datetime.isoformat()
    )

    current_catalogue = convert_migrated_sale_predicate_to_catalogue_info(
        promotion.rules.first().catalogue_predicate
    )
    updated_webhook_mock.assert_called_once_with(
        promotion, previous_catalogue, current_catalogue
    )
    sale_toggle_mock.assert_not_called()
    update_products_discounted_prices_for_promotion_task_mock.assert_called_once()


@freeze_time("2020-03-18 12:00:00")
@patch(
    "saleor.product.tasks.update_products_discounted_prices_for_promotion_task.delay"
)
@patch("saleor.plugins.manager.PluginsManager.sale_toggle")
@patch("saleor.plugins.manager.PluginsManager.sale_updated")
def test_update_sale_start_date_before_current_date_notification_sent(
    updated_webhook_mock,
    sale_toggle_mock,
    update_products_discounted_prices_for_promotion_task_mock,
    staff_api_client,
    sale,
    permission_manage_discounts,
):
    """Ensure the sale_toggle notification is sent and the notification date is set
    when the start date is set before current date and the notification hasn't been sent
    before.
    """
    # given
    query = SALE_UPDATE_MUTATION

    # Set discount value type to 'fixed' and change it in mutation
    sale.type = DiscountValueType.FIXED
    sale.notification_sent_datetime = None
    sale.save(update_fields=["type", "notification_sent_datetime"])
    previous_catalogue = convert_catalogue_info_to_global_ids(
        fetch_catalogue_info(sale)
    )
    start_date = timezone.now() - timedelta(days=1)
    convert_sales_to_promotions()

    variables = {
        "id": graphene.Node.to_global_id("Sale", sale.id),
        "input": {"startDate": start_date},
    }

    # when
    response = staff_api_client.post_graphql(
        query, variables, permissions=[permission_manage_discounts]
    )

    # then
    content = get_graphql_content(response)
    assert not content["data"]["saleUpdate"]["errors"]
    data = content["data"]["saleUpdate"]["sale"]
    assert data["startDate"] == start_date.isoformat()
    promotion = Promotion.objects.get(old_sale_id=sale.id)
    assert promotion.start_date.isoformat() == start_date.isoformat()
    assert promotion.last_notification_scheduled_at == timezone.now()

    current_catalogue = convert_migrated_sale_predicate_to_catalogue_info(
        promotion.rules.first().catalogue_predicate
    )
    updated_webhook_mock.assert_called_once_with(
        promotion, previous_catalogue, current_catalogue
    )

    sale_toggle_mock.assert_called_once_with(promotion, current_catalogue)
    update_products_discounted_prices_for_promotion_task_mock.assert_called_once()


@freeze_time("2020-03-18 12:00:00")
@patch(
    "saleor.product.tasks.update_products_discounted_prices_for_promotion_task.delay"
)
@patch("saleor.plugins.manager.PluginsManager.sale_toggle")
@patch("saleor.plugins.manager.PluginsManager.sale_updated")
def test_update_sale_end_date_after_current_date_notification_not_sent(
    updated_webhook_mock,
    sale_toggle_mock,
    update_products_discounted_prices_for_promotion_task_mock,
    staff_api_client,
    sale,
    permission_manage_discounts,
):
    """Ensure the notification is not sent when the end date is set after
    the current date.
    """
    # given
    query = SALE_UPDATE_MUTATION

    previous_catalogue = convert_catalogue_info_to_global_ids(
        fetch_catalogue_info(sale)
    )
    sale.start_date = timezone.now() - timedelta(days=1)
    sale.save(update_fields=["start_date"])
    end_date = timezone.now() + timedelta(days=1)
    convert_sales_to_promotions()

    variables = {
        "id": graphene.Node.to_global_id("Sale", sale.id),
        "input": {"endDate": end_date},
    }

    # when
    response = staff_api_client.post_graphql(
        query, variables, permissions=[permission_manage_discounts]
    )

    # then
    content = get_graphql_content(response)
    assert not content["data"]["saleUpdate"]["errors"]
    data = content["data"]["saleUpdate"]["sale"]

    assert data["endDate"] == end_date.isoformat()
    promotion = Promotion.objects.get(old_sale_id=sale.id)
    assert promotion.end_date.isoformat() == end_date.isoformat()
    assert promotion.last_notification_scheduled_at is None

    current_catalogue = convert_migrated_sale_predicate_to_catalogue_info(
        promotion.rules.first().catalogue_predicate
    )
    updated_webhook_mock.assert_called_once_with(
        promotion, previous_catalogue, current_catalogue
    )
    sale_toggle_mock.assert_not_called()
    update_products_discounted_prices_for_promotion_task_mock.assert_called_once()


@freeze_time("2020-03-18 12:00:00")
@patch(
    "saleor.product.tasks.update_products_discounted_prices_for_promotion_task.delay"
)
@patch("saleor.plugins.manager.PluginsManager.sale_toggle")
@patch("saleor.plugins.manager.PluginsManager.sale_updated")
def test_update_sale_end_date_before_current_date_notification_already_sent(
    updated_webhook_mock,
    sale_toggle_mock,
    update_products_discounted_prices_for_promotion_task_mock,
    staff_api_client,
    sale,
    permission_manage_discounts,
):
    """Ensure the notification is sent when the end date is set before
    current date, the notification was already sent but the end date was not set before.
    It means we need to notify about ending the sale.
    """
    # given
    query = SALE_UPDATE_MUTATION
    now = timezone.now()

    # Set discount value type to 'fixed' and change it in mutation
    sale.type = DiscountValueType.FIXED
    notification_sent_datetime = now - timedelta(minutes=5)
    sale.notification_sent_datetime = notification_sent_datetime
    sale.start_date = now - timedelta(days=2)
    sale.save(update_fields=["type", "notification_sent_datetime", "start_date"])
    previous_catalogue = convert_catalogue_info_to_global_ids(
        fetch_catalogue_info(sale)
    )
    end_date = now - timedelta(days=1)
    convert_sales_to_promotions()

    variables = {
        "id": graphene.Node.to_global_id("Sale", sale.id),
        "input": {"endDate": end_date},
    }

    # when
    response = staff_api_client.post_graphql(
        query, variables, permissions=[permission_manage_discounts]
    )

    # then
    content = get_graphql_content(response)
    assert not content["data"]["saleUpdate"]["errors"]
    data = content["data"]["saleUpdate"]["sale"]
    assert data["endDate"] == end_date.isoformat()
    promotion = Promotion.objects.get(old_sale_id=sale.id)
    assert promotion.end_date.isoformat() == end_date.isoformat()
    assert promotion.last_notification_scheduled_at == now

    current_catalogue = convert_migrated_sale_predicate_to_catalogue_info(
        promotion.rules.first().catalogue_predicate
    )
    updated_webhook_mock.assert_called_once_with(
        promotion, previous_catalogue, current_catalogue
    )
    sale_toggle_mock.assert_called_once_with(promotion, current_catalogue)
    update_products_discounted_prices_for_promotion_task_mock.assert_called_once()


@freeze_time("2020-03-18 12:00:00")
@patch(
    "saleor.product.tasks.update_products_discounted_prices_for_promotion_task.delay"
)
@patch("saleor.plugins.manager.PluginsManager.sale_toggle")
@patch("saleor.plugins.manager.PluginsManager.sale_updated")
def test_update_sale_end_date_before_current_date_notification_sent(
    updated_webhook_mock,
    sale_toggle_mock,
    update_products_discounted_prices_for_promotion_task_mock,
    staff_api_client,
    sale,
    permission_manage_discounts,
):
    """Ensure the sale_toggle notification is sent and the notification date is set
    when the end date is set before current date and the notification hasn't been sent
    before.
    """
    # given
    query = SALE_UPDATE_MUTATION

    # Set discount value type to 'fixed' and change it in mutation
    sale.type = DiscountValueType.FIXED
    sale.notification_sent_datetime = None
    sale.start_date = timezone.now() - timedelta(days=2)
    sale.save(update_fields=["type", "notification_sent_datetime", "start_date"])
    previous_catalogue = convert_catalogue_info_to_global_ids(
        fetch_catalogue_info(sale)
    )
    end_date = timezone.now() - timedelta(days=1)
    convert_sales_to_promotions()

    variables = {
        "id": graphene.Node.to_global_id("Sale", sale.id),
        "input": {"endDate": end_date},
    }

    # when
    response = staff_api_client.post_graphql(
        query, variables, permissions=[permission_manage_discounts]
    )

    # then
    content = get_graphql_content(response)
    assert not content["data"]["saleUpdate"]["errors"]
    data = content["data"]["saleUpdate"]["sale"]
    assert data["endDate"] == end_date.isoformat()
    promotion = Promotion.objects.get(old_sale_id=sale.id)
    assert promotion.end_date.isoformat() == end_date.isoformat()
    assert promotion.last_notification_scheduled_at == timezone.now()

    current_catalogue = convert_migrated_sale_predicate_to_catalogue_info(
        promotion.rules.first().catalogue_predicate
    )
    updated_webhook_mock.assert_called_once_with(
        promotion, previous_catalogue, current_catalogue
    )
    sale_toggle_mock.assert_called_once_with(promotion, current_catalogue)
    update_products_discounted_prices_for_promotion_task_mock.assert_called_once()


@patch(
    "saleor.product.tasks.update_products_discounted_prices_for_promotion_task.delay"
)
@patch("saleor.plugins.manager.PluginsManager.sale_updated")
def test_update_sale_categories(
    updated_webhook_mock,
    update_products_discounted_prices_for_promotion_task_mock,
    staff_api_client,
    sale,
    permission_manage_discounts,
    product_list,
    non_default_category,
):
    # given
    query = SALE_UPDATE_MUTATION

    previous_catalogue = convert_catalogue_info_to_global_ids(
        fetch_catalogue_info(sale)
    )
    convert_sales_to_promotions()
    new_category_id = graphene.Node.to_global_id("Category", non_default_category.id)

    variables = {
        "id": graphene.Node.to_global_id("Sale", sale.id),
        "input": {
            "categories": [new_category_id],
        },
    }

    # when
    response = staff_api_client.post_graphql(
        query, variables, permissions=[permission_manage_discounts]
    )

    # then
    content = get_graphql_content(response)
    assert not content["data"]["saleUpdate"]["errors"]
    promotion = Promotion.objects.get(old_sale_id=sale.id)
    predicate = promotion.rules.first().catalogue_predicate
    current_catalogue = convert_migrated_sale_predicate_to_catalogue_info(predicate)
    assert current_catalogue["categories"] == {new_category_id}

    updated_webhook_mock.assert_called_once_with(
        promotion, previous_catalogue, current_catalogue
    )
    update_products_discounted_prices_for_promotion_task_mock.assert_called_once()


@patch(
    "saleor.product.tasks.update_products_discounted_prices_for_promotion_task.delay"
)
@patch("saleor.plugins.manager.PluginsManager.sale_updated")
def test_update_sale_collections(
    updated_webhook_mock,
    update_products_discounted_prices_for_promotion_task_mock,
    staff_api_client,
    sale,
    permission_manage_discounts,
    product_list,
    published_collection,
):
    # given
    query = SALE_UPDATE_MUTATION

    previous_catalogue = convert_catalogue_info_to_global_ids(
        fetch_catalogue_info(sale)
    )
    new_collection_id = graphene.Node.to_global_id(
        "Collection", published_collection.id
    )
    convert_sales_to_promotions()

    variables = {
        "id": graphene.Node.to_global_id("Sale", sale.id),
        "input": {
            "collections": [new_collection_id],
        },
    }

    # when
    response = staff_api_client.post_graphql(
        query, variables, permissions=[permission_manage_discounts]
    )

    # then
    content = get_graphql_content(response)
    assert not content["data"]["saleUpdate"]["errors"]
    promotion = Promotion.objects.get(old_sale_id=sale.id)
    predicate = promotion.rules.first().catalogue_predicate
    current_catalogue = convert_migrated_sale_predicate_to_catalogue_info(predicate)
    assert current_catalogue["collections"] == {new_collection_id}

    updated_webhook_mock.assert_called_once_with(
        promotion, previous_catalogue, current_catalogue
    )
    update_products_discounted_prices_for_promotion_task_mock.assert_called_once()


@patch(
    "saleor.product.tasks.update_products_discounted_prices_for_promotion_task.delay"
)
@patch("saleor.plugins.manager.PluginsManager.sale_updated")
def test_update_sale_variants(
    updated_webhook_mock,
    update_products_discounted_prices_for_promotion_task_mock,
    staff_api_client,
    sale,
    permission_manage_discounts,
    product_list,
    preorder_variant_global_threshold,
):
    # given
    query = SALE_UPDATE_MUTATION

    previous_catalogue = convert_catalogue_info_to_global_ids(
        fetch_catalogue_info(sale)
    )
    convert_sales_to_promotions()
    new_variant_id = graphene.Node.to_global_id(
        "ProductVariant", preorder_variant_global_threshold.id
    )

    variables = {
        "id": graphene.Node.to_global_id("Sale", sale.id),
        "input": {
            "variants": [new_variant_id],
        },
    }

    # when
    response = staff_api_client.post_graphql(
        query, variables, permissions=[permission_manage_discounts]
    )

    # then
    content = get_graphql_content(response)
    assert not content["data"]["saleUpdate"]["errors"]
    promotion = Promotion.objects.get(old_sale_id=sale.id)
    predicate = promotion.rules.first().catalogue_predicate
    current_catalogue = convert_migrated_sale_predicate_to_catalogue_info(predicate)
    assert current_catalogue["variants"] == {new_variant_id}

    updated_webhook_mock.assert_called_once_with(
        promotion, previous_catalogue, current_catalogue
    )
    update_products_discounted_prices_for_promotion_task_mock.assert_called_once()


@patch(
    "saleor.product.tasks.update_products_discounted_prices_for_promotion_task.delay"
)
@patch("saleor.plugins.manager.PluginsManager.sale_updated")
def test_update_sale_products(
    updated_webhook_mock,
    update_products_discounted_prices_for_promotion_task_mock,
    staff_api_client,
    sale,
    permission_manage_discounts,
    product_list,
    published_collection,
):
    # given
    query = SALE_UPDATE_MUTATION

    previous_catalogue = convert_catalogue_info_to_global_ids(
        fetch_catalogue_info(sale)
    )
    convert_sales_to_promotions()
    new_product_id = graphene.Node.to_global_id("Product", product_list[-1].id)

    variables = {
        "id": graphene.Node.to_global_id("Sale", sale.id),
        "input": {
            "products": [new_product_id],
        },
    }

    # when
    response = staff_api_client.post_graphql(
        query, variables, permissions=[permission_manage_discounts]
    )

    # then
    content = get_graphql_content(response)
    assert not content["data"]["saleUpdate"]["errors"]
    promotion = Promotion.objects.get(old_sale_id=sale.id)
    predicate = promotion.rules.first().catalogue_predicate
    current_catalogue = convert_migrated_sale_predicate_to_catalogue_info(predicate)
    assert current_catalogue["products"] == {new_product_id}

    updated_webhook_mock.assert_called_once_with(
        promotion, previous_catalogue, current_catalogue
    )
    update_products_discounted_prices_for_promotion_task_mock.assert_called_once()


@freeze_time("2020-03-18 12:00:00")
@patch(
    "saleor.product.tasks.update_products_discounted_prices_for_promotion_task.delay"
)
@patch("saleor.plugins.manager.PluginsManager.sale_toggle")
@patch("saleor.plugins.manager.PluginsManager.sale_updated")
def test_update_sale_end_date_before_start_date(
    updated_webhook_mock,
    sale_toggle_mock,
    update_products_discounted_prices_for_promotion_task_mock,
    staff_api_client,
    sale,
    permission_manage_discounts,
):
    # given
    query = SALE_UPDATE_MUTATION

    sale.start_date = timezone.now() + timedelta(days=1)
    sale.save(update_fields=["start_date"])
    end_date = timezone.now() - timedelta(days=1)
    convert_sales_to_promotions()

    variables = {
        "id": graphene.Node.to_global_id("Sale", sale.id),
        "input": {"endDate": end_date},
    }

    # when
    response = staff_api_client.post_graphql(
        query, variables, permissions=[permission_manage_discounts]
    )

    # then
    content = get_graphql_content(response)
    assert not content["data"]["saleUpdate"]["sale"]
    errors = content["data"]["saleUpdate"]["errors"]
    assert len(errors) == 1
    assert errors[0]["field"] == "endDate"
    assert errors[0]["code"] == DiscountErrorCode.INVALID.name
    updated_webhook_mock.assert_not_called()
    sale_toggle_mock.assert_not_called()
    update_products_discounted_prices_for_promotion_task_mock.assert_not_called()


@freeze_time("2020-03-18 12:00:00")
def test_update_sale_with_none_values(
    staff_api_client,
    sale,
    permission_manage_discounts,
):
    """Ensure that non-required fields can be nullified."""

    # given
    query = SALE_UPDATE_MUTATION

    sale.name = "Sale name"
    sale.type = DiscountValueType.FIXED
    start_date = timezone.now() + timedelta(days=1)
    sale.start_date = start_date
    sale.end_date = timezone.now() + timedelta(days=5)
    sale.save(update_fields=["name", "type", "start_date", "end_date"])
    convert_sales_to_promotions()

    variables = {
        "id": graphene.Node.to_global_id("Sale", sale.id),
        "input": {
            "name": None,
            "startDate": None,
            "endDate": None,
            "type": None,
            "collections": [],
            "categories": [],
            "products": [],
            "variants": [],
        },
    }

    # when
    response = staff_api_client.post_graphql(
        query, variables, permissions=[permission_manage_discounts]
    )

    # then
    content = get_graphql_content(response)
    assert not content["data"]["saleUpdate"]["errors"]
    data = content["data"]["saleUpdate"]["sale"]
    assert data["type"] == DiscountValueType.FIXED.upper()
    assert data["name"] == "Sale name"
    assert data["startDate"] == start_date.isoformat()
    assert not data["endDate"]

    promotion = Promotion.objects.get(old_sale_id=sale.id)
    assert promotion.start_date.isoformat() == start_date.isoformat()
    assert promotion.start_date == start_date
    assert not promotion.end_date

    rule = promotion.rules.first()
    assert rule.reward_value_type == DiscountValueType.FIXED
    assert not rule.catalogue_predicate
