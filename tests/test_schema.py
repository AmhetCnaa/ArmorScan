"""
Unit tests for API Schema Parser & GraphQL Auditor (schema.py).
"""

import json
from pathlib import Path
import pytest
import respx

from armorscan.core.client import HttpClient
from armorscan.core.schema import (
    ApiEndpoint,
    ApiParameter,
    GraphQLAuditor,
    OpenApiParser,
)

SAMPLE_OPENAPI_3_JSON = """
{
  "openapi": "3.0.0",
  "info": {"title": "Test API", "version": "1.0.0"},
  "paths": {
    "/users/{userId}": {
      "get": {
        "summary": "Get user details",
        "parameters": [
          {"name": "userId", "in": "path", "required": true, "schema": {"type": "integer"}},
          {"name": "include_orders", "in": "query", "schema": {"type": "boolean"}}
        ]
      },
      "put": {
        "summary": "Update user",
        "parameters": [
          {"name": "userId", "in": "path", "required": true, "schema": {"type": "integer"}}
        ],
        "requestBody": {
          "content": {
            "application/json": {
              "schema": {
                "type": "object",
                "properties": {
                  "email": {"type": "string"},
                  "age": {"type": "integer"}
                },
                "required": ["email"]
              }
            }
          }
        }
      }
    }
  }
}
"""

SAMPLE_SWAGGER_2_YAML = """
swagger: "2.0"
info:
  title: "Legacy Petstore"
  version: "1.0"
paths:
  /pets:
    get:
      summary: "List all pets"
      parameters:
        - name: "limit"
          in: "query"
          type: "integer"
        - name: "tags"
          in: "query"
          type: "string"
    post:
      summary: "Create a pet"
      parameters:
        - name: "name"
          in: "formData"
          type: "string"
          required: true
"""

SAMPLE_GRAPHQL_INTROSPECTION = {
    "data": {
        "__schema": {
            "queryType": {"name": "Query"},
            "mutationType": {"name": "Mutation"},
            "types": [
                {
                    "name": "Query",
                    "kind": "OBJECT",
                    "fields": [
                        {"name": "me"},
                        {"name": "orders"},
                        {"name": "__typename"}
                    ]
                },
                {
                    "name": "Mutation",
                    "kind": "OBJECT",
                    "fields": [
                        {"name": "login"},
                        {"name": "deleteUser"}
                    ]
                }
            ]
        }
    }
}


def test_parse_openapi_3_json():
    endpoints = OpenApiParser.parse_content(SAMPLE_OPENAPI_3_JSON)
    assert len(endpoints) == 2

    # GET /users/{userId}
    get_ep = next(e for e in endpoints if e.method == "GET")
    assert get_ep.path == "/users/{userId}"
    assert get_ep.summary == "Get user details"
    assert len(get_ep.path_parameters) == 1
    assert get_ep.path_parameters[0].name == "userId"
    assert len(get_ep.query_parameters) == 1
    assert get_ep.query_parameters[0].name == "include_orders"

    # PUT /users/{userId}
    put_ep = next(e for e in endpoints if e.method == "PUT")
    assert put_ep.method == "PUT"
    assert len(put_ep.body_parameters) == 2
    body_names = [p.name for p in put_ep.body_parameters]
    assert "email" in body_names
    assert "age" in body_names


def test_parse_swagger_2_yaml(tmp_path: Path):
    endpoints = OpenApiParser.parse_content(SAMPLE_SWAGGER_2_YAML)
    assert len(endpoints) == 2

    get_ep = next(e for e in endpoints if e.method == "GET")
    assert get_ep.path == "/pets"
    assert len(get_ep.query_parameters) == 2

    post_ep = next(e for e in endpoints if e.method == "POST")
    assert post_ep.path == "/pets"
    assert len(post_ep.body_parameters) == 1
    assert post_ep.body_parameters[0].name == "name"

    # Test file reading
    file_path = tmp_path / "swagger.yaml"
    file_path.write_text(SAMPLE_SWAGGER_2_YAML, encoding="utf-8")
    from_file = OpenApiParser.parse_file(file_path)
    assert len(from_file) == 2


def test_build_test_url():
    ep = ApiEndpoint(
        path="/items/{id}/reviews/{reviewId}",
        method="GET",
        parameters=[
            ApiParameter(name="id", location="path", param_type="integer"),
            ApiParameter(name="reviewId", location="path", param_type="string"),
            ApiParameter(name="sort", location="query", param_type="string"),
            ApiParameter(name="limit", location="query", param_type="integer"),
        ]
    )
    url = ep.build_test_url("https://api.example.com")
    assert "https://api.example.com/items/1/reviews/test_val" in url
    assert "sort=test" in url
    assert "limit=1" in url


@pytest.mark.asyncio
async def test_graphql_auditor_success():
    async with HttpClient(proxy=None) as client:
        with respx.mock(base_url="https://gql.example.com", assert_all_called=False) as respx_mock:
            respx_mock.post("/graphql").respond(
                status_code=200,
                json=SAMPLE_GRAPHQL_INTROSPECTION,
                headers={"Content-Type": "application/json"}
            )

            is_active, gql_url, endpoints = await GraphQLAuditor.audit_graphql(
                client, "https://gql.example.com"
            )

            assert is_active is True
            assert gql_url == "https://gql.example.com/graphql"
            assert len(endpoints) == 4  # me, orders, login, deleteUser (__typename filtered)
            ep_paths = [e.path for e in endpoints]
            assert "/graphql#query:me" in ep_paths
            assert "/graphql#query:orders" in ep_paths
            assert "/graphql#mutation:deleteUser" in ep_paths


@pytest.mark.asyncio
async def test_graphql_auditor_disabled():
    async with HttpClient(proxy=None) as client:
        with respx.mock(base_url="https://gql-secure.example.com", assert_all_called=False) as respx_mock:
            respx_mock.post("/graphql").respond(
                status_code=400,
                json={"errors": [{"message": "Introspection is disabled"}]},
                headers={"Content-Type": "application/json"}
            )
            respx_mock.post(respx.patterns.M("api/graphql")).respond(status_code=404)
            respx_mock.post(respx.patterns.M("v1/graphql")).respond(status_code=404)

            is_active, gql_url, endpoints = await GraphQLAuditor.audit_graphql(
                client, "https://gql-secure.example.com"
            )

            assert is_active is False
            assert gql_url is None
            assert len(endpoints) == 0


@pytest.mark.asyncio
async def test_openapi_discover_and_parse():
    async with HttpClient(proxy=None) as client:
        with respx.mock(base_url="https://api-discovered.example.com", assert_all_called=False) as respx_mock:
            respx_mock.get("/openapi.json").respond(
                status_code=200,
                text=SAMPLE_OPENAPI_3_JSON,
                headers={"Content-Type": "application/json"}
            )

            url, endpoints = await OpenApiParser.discover_and_parse(
                client, "https://api-discovered.example.com"
            )
            assert url == "https://api-discovered.example.com/openapi.json"
            assert len(endpoints) == 2
