# docs/user_docs.py

from http import HTTPStatus
from src.modules.auth.schemas import UserLoginSchema
from openapi.components import pagination_parameters, pagination_metadata

user_list_doc = {
    "description": "Retrieve a paginated list of users.",
    "parameters": pagination_parameters,
    "responses": {
        HTTPStatus.OK.value: {
            "description": "A paginated list of users.",
            "content": {
                "application/json": {
                    "schema": {
                        "type": "object",
                        "properties": {
                            "data": {"type": "array", "items": UserLoginSchema},
                            "meta": pagination_metadata,
                        },
                    }
                }
            },
        }
    },
}
