# wsgi
This is simple wsgi framework. It is not for production use, but only for
learning purpose. It is developped with the following properties:
* use http-parser to parse the incoming HTTP request.
* fork a worker for each incoming HTTP request.

The wsgiserver.py script takes as argument the module name, and a callable
from this module (module:callable).

```
$ virtualenv venv
$ source venv/bin/activate
(venv)$ pip install http-parser
(venv)$ ./wsgiserver.py app:application
```

# todo

Do not use the fork model anymore, but instead use an asynchronous
model by using for example gevent.
