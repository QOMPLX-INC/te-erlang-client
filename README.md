# TimeEngine HTTP Client
## Overview

**mdhc** is an Erlang client for TimeEngine, using the HTTP
interface

## Quick Start
   You must have [Erlang/OTP R24](http://erlang.org/download.html) or later and a GNU-style
   build system to compile and run **mdhc**.

   rebar3 is used to build the project, so that you should install the script rebar3 from
   binary or sources and make sure it is copied to somewhere in your $PATH.

   You can generate documentation with

	$ make doc

  and run the test framework with

	$ make ct

   The TimeEngine Erlang HTTP Client is a library application. For a
   quick start example, first, start up an Erlang shell with the path to
   **mdhc** and all dependencies included, then start **sasl** and
   **gun** or **hackney** http client libs.

   Selection of http client library is defined by Mdtsdb client options.
   Available options are: gun and hackney. If hackney is selected as the
   http client lib, it uses connection pool from the tuple {pool,
   my_pool}. By default http client library is hackney.

   Note, that in the current version of the TimeEngine HTTP Client
   streaming insertion of data (functions "insert_chunked(...)") that
   utilizes a function generator to continuously produce data to insert
   into TimeEngine is supported only by the hackney http client library.

   Next, create your client and walk through the basic workflow using the overview from
   the generated documentation.

   Please refer to test cases and the generated documentation for more information.

	$ make doc && open doc/index.html

## API review: Geo Data upload

    send_streaming_geo_data() and send_events_geo_data() API methods provide
    upload of GeoJSON, TopoJSON and KML encoded data using the following
    assumptions.

### GeoJSON

    Data set is presented by "FeatureCollection" or "Feature" GeoJSON object.
    It is important to fill properly "properties" field of the GeoJSON object.
    Mdtsdb service searches for several required parameters (timestamp, sensor
    identifier, sensor value) in this field. Namely:

    1) timestamp is placed into "timestamp" field
    2) sensor alias (identifier) is placed into "id" field
    3) value of the sensor at this given moment of time in the given geometry
       is placed into "value" field

    E.g.,

```json
{
    "type": "FeatureCollection",
    "features": [{
        "type": "Feature",
        "geometry": {
            "type": "Point",
            "coordinates": [102.0, 0.5]
        },
        "properties": {
            "id": "0",
            "timestamp": 1447360023,
            "value": {
                "prop0": "avalue0",
                "prop1": "Point"
            }
        }
    },
    {
        "type": "Feature",
        "geometry": {
            "type": "LineString",
            "coordinates": [
                [102.0, 0.0],
                [103.0, 1.0],
                [104.0, 0.0],
                [105.0, 1.0]
            ]
        },
        "properties": {
            "id": "0",
            "timestamp": 1447360020,
            "value": {
                "prop0": "avalue0",
                "prop1": "LineString"
            }
        }
    },
    {
        "type": "Feature",
        "geometry": {
            "type": "Polygon",
            "coordinates": [
                [
                    [100.0, 0.0],
                    [101.0, 0.0],
                    [101.0, 1.0],
                    [100.0, 1.0],
                    [100.0, 0.0]
                ]
            ]
        },
        "properties": {
            "id": "0",
            "timestamp": 1447360021,
            "value": {
                "prop0": "10000",
                "prop1": "LineString"
            }
        }
    }]
}
```

### TopoJSON

    Data set is presented by a TopoJSON object with mandatory fields of "type"
    and "objects". Each record within "objects" structure presents a sensor
    value (a geo-related event), and it is important to fill properly "properties"
    field of each record within "objects" field. Mdtsdb service searches for
    several required parameters (timestamp, sensor identifier, sensor value)
    in this field. Namely:

    1) timestamp is placed into "timestamp" field
    2) sensor alias (identifier) is placed into "id" field
    3) value of the sensor at this given moment of time in the given geometry
       is placed into "value" field

    E.g.,

```json
{
  "type": "Topology",
  "objects": {
      "example": {
          "type": "GeometryCollection",
          "properties": {
              "id": "0",
              "timestamp": 1447360025,
              "value": {
                  "prop0": "abcdefgh",
                  "prop1": "GeometryCollection"
              }
          },
          "geometries":
          [
            {
                "type": "Point",
                "coordinates": [100.0, 0.0]
            },
            {
                "type": "LineString",
                "arcs": [-2]
            }
          ]
      },
      "example2": {
          "type": "MultiLineString",
          "properties": {
              "id": "0",
              "timestamp": 1447360020,
              "value": {
                  "prop0": "avalue0",
                  "prop1": "LineString"
              }
          },
          "arcs": [[0]]
      }
  },
  "arcs": [
    [[102.0, 0], [103, 1], [104, 0], [105, 1]],
    [[100.0, 0], [101.1, 0.0], [101.4, 1], [100, 1], [100.0, 0]],
    [[100.0, 10], [101.2, 10.0], [101.3, 11], [100.0, 11], [100.0, 10]]
  ]
}
```

### KML

    1) Timestamp is placed into <timestamp> <when> construction
    2) Sensor alias (identifier) is placed into <name> tag
    3) Value of the sensor at this given moment of time in the given geometry
       is placed into <description> tag. If value is not a scalar value, but
       rather a list of properties, it can be wraped in CDATA block inside
       <description> tag in Json format, like in:

	<description>
		<![CDATA[ {"field1":"abc","field2":123} ]]>
	</description>

# Copyright
Copyright 2015—2021 QOMPLX, Inc. — All Rights Reserved.  No License Granted.
