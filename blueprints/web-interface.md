FORMAT: 1A

# Community Announcer API
In this API makes your community announcements.

## Health Check [/ping]

### Retrieve a Pong Message [GET]
This action returns Pong message.

+ Response

    + StatusCode

            200

    + Headers

            server: Cowboy
            connection: close
            content-type: text/plain; charset=utf-8
            date: Sun, 22 Apr 2018 20:55:42 GMT
            content-length: 4
            via: 1.1 vegur

    + Body

            pong
