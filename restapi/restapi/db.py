from fastapi.exceptions import HTTPException

from .models import ParsedScanRequest, InvalidQueryString
from google.cloud.firestore_v1.async_query import AsyncQuery
from google.cloud.firestore_v1.async_collection import AsyncCollectionReference

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Union
    from google.cloud.firestore_v1.base_query import BaseQuery


async def construct_query(
    collection: AsyncCollectionReference, req: ParsedScanRequest
) -> AsyncQuery:
    try:
        queries = req.get_queries()
    except InvalidQueryString as e:
        raise HTTPException(status_code=400, detail=e.args)

    # Filter
    query = collection._query()  # type: Union[AsyncQuery, BaseQuery]
    for q in queries:
        query = query.where(q.field, q.operator, q.value)

    # Sort
    if req.order_by:
        query = query.order_by(
            req.order_by.field, direction=req.order_by.direction.value
        )

    # Limit
    if req.limit:
        if req.limit.last:
            query = query.limit_to_last(req.limit.limit)
        else:
            query = query.limit(req.limit.limit)

    return query
