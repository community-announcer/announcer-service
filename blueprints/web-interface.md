FORMAT: 1A

# Community Announcer API
In this API makes your community announcements.


## User Operations [/user/{name}]

+ Parameters
    + name: foo (string, required)


### Retrieve a User Without Value [GET]
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
                "status": "no value",
                "user": "foo"
            }
