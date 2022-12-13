# kbr-tools-tornado
tornado library, can be added to kbr-tools


## auth extension

By default rest-auth extension is also installed.

In a script do:

```
import kbr.tornado.auth_rest as auth_rest


# where defining the endpoints:


    urls = [('/', RootHandler),
            (r'/welcome/?$',             WelcomeHandler),
            ] + auth_rest.init( database_uri, introspection_url,
                                client_id, client_secret )



```