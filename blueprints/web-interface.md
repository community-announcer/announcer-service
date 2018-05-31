FORMAT: 1A

# Community Announcer API
In this API makes your community announcements.

## Standard API Definitions

### Retrieve Informations [GET]

+ Response 204

    + Headers

            server: Cowboy
            connection: close
            content-type: application/json; charset=utf-8
            date: Sun, 22 Apr 2018 20:55:42 GMT
            content-length: 4
            via: 1.1 vegur

## API Public Operations [/api/public]

### Retrieve a Public Response [GET]
This action returns a Not Found User.

+ Response 200

    + Headers

            server: Cowboy
            connection: close
            content-type: application/json; charset=utf-8
            date: Sun, 22 Apr 2018 20:55:42 GMT
            content-length: 4
            via: 1.1 vegur

    + Body

            {
                "message": "public api"
            }
