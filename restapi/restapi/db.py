from .models import Filter, ReportRequest
from google.cloud.firestore_v1.async_query import AsyncQuery
from google.cloud.firestore_v1.async_collection import AsyncCollectionReference
from google.cloud import firestore
from typing import Any, AsyncGenerator, Optional


async def construct_query(
    collection: AsyncCollectionReference, req: ReportRequest
) -> AsyncQuery:  # TODO: find out if we return an AsyncQuery or a BaseQuery (thanks gcloud-aio..)
    # Filter
    query = collection.where(*(req.get_query()))
    # Sort
    if req.order_by:
        query = query.order_by("timestamp", direction=firestore.Query.DESCENDING)
    # Limit
    if req.limit:
        query = query.limit(req.limit)
    return query


async def filter_documents(
    docs: AsyncGenerator[Optional[dict[str, Any]], None], docfilter: Filter
) -> AsyncGenerator[dict[str, Any], None]:
    """Filter a stream of documents given a user-defined document filter.

    Parameters
    ----------
    docs : AsyncGenerator[DocumentSnapshot, None]
        Async generator of DocumentSnapshot objects.
    docfilter : Filter
        User-defined filter.

    Returns
    -------
    AsyncGenerator[dict[str, Any], None]
        Returns an async generator of filtered documents converted to dicts.
    """

    def pred(key: str, value: Any, doc: dict[str, Any]) -> bool:
        # TODO: improve robustness of predicate function
        # Use doc.get(key) and check for None
        return doc[key] >= value

    async for doc in docs:
        if doc is None:  # filter None
            continue
        for k, v in docfilter.get_filters():
            should_yield = pred(k, v, doc)
            if should_yield:
                yield doc
                break
