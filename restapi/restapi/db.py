import asyncio
from fastapi.exceptions import HTTPException

from .models import Filter, ParsedScanRequest, InvalidQueryString
from google.cloud.firestore_v1.async_query import AsyncQuery
from google.cloud.firestore_v1.async_collection import AsyncCollectionReference
from google.cloud import firestore
from google.cloud.firestore_v1.async_document import DocumentSnapshot
from typing import Any, AsyncGenerator, Iterable


async def construct_query(
    collection: AsyncCollectionReference, req: ParsedScanRequest
) -> AsyncQuery:
    # Filter
    query = collection.where(*(req.get_query()))
    # Sort
    if req.order_by:
        query = query.order_by("scanned", direction=firestore.Query.DESCENDING)
    # Limit
    if req.limit:
        query = query.limit(req.limit)
    return query


async def filter_documents(
    docs: AsyncGenerator[dict[str, Any], None], docfilter: Filter
) -> AsyncGenerator[dict[str, Any], None]:
    def pred(key: str, value: Any, doc: dict[str, Any]) -> bool:
        # TODO: improve robustness of predicate function
        # Use doc.get(key) and check for None
        return doc[key] >= value

    async for doc in docs:
        for k, v in docfilter.get_filters():
            should_yield = pred(k, v, doc)
            if should_yield:
                yield doc
                break
