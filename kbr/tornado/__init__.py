import json
import tornado
import urllib

from tornado.ioloop import IOLoop
from tornado.web import Application

from tornado.web import RequestHandler, HTTPError

from uuid import UUID
from decimal import Decimal
import datetime

import kbr.log_utils as logger

import pprint as pp

token = None
token_cache = {}

environment = 'production'

#reference to user provided function for introspecion and getting acls
introspection_func = None
userprofile_func = None


# bespoke decoder to handle UUID and timestamps
class UUIDEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, UUID):
            # if the obj is uuid, we simply return the value of uuid
            return obj.hex
        if isinstance(obj, Decimal):
            # if the obj is decimal, we simply return the value of uuid
            return float(obj)
        if isinstance(obj, (datetime.date, datetime.datetime)):
            return obj.isoformat()

        return json.JSONEncoder.default(self, obj)



class BaseHandler( RequestHandler ):

    def _can(self, endpoint:str, method:str) -> bool:
        if environment == 'developments':
            return True

        userprofile = self.userProfile()

        if userprofile.get('superuser', False):
            return True

        acls = userprofile['acls']

        if endpoint in acls and acls[ endpoint ] and method in acls[ endpoint ]:
            return acls[ endpoint ][ method ]

        self.send_response_403(f"No access to {method} on {endpoint}")

    def canCreate(self, endpoint:str) -> bool:
        return self._can( endpoint, 'can_create')

    def canRead(self, endpoint:str) -> bool:
        return self._can( endpoint, 'can_read')

    def canUpdate(self, endpoint:str) -> bool:
        return self._can( endpoint, 'can_update')

    def canDelete(self, endpoint:str) -> bool:
        return self._can( endpoint, 'can_delete')

    def remote_ip(self):
        x_real_ip = self.request.headers.get("X-Real-IP")
        remote_ip = x_real_ip or self.request.remote_ip

        return remote_ip


    def prepare(self):
        ''' change the strings from bytestring to utf8 '''

        self.form_data = {
            key: [val.decode('utf8') for val in val_list]
            for key, val_list in self.request.arguments.items()
        }


    def arguments(self):

        values = {}
        for argument in self.request.arguments:
            values[ argument ] = self.get_argument( argument )

        return values

    def valid_arguments(self, values:dict, valid:list) -> dict:


        for key in values:
            if key not in valid:
                return self.send_response_400(data="Invalid value {}".format( key ))

        return values

    def require_arguments(self, values:dict, required:list) -> dict:
#        self.valid_arguments( values, required )

        for key in required:
            if key not in values:
                return self.send_response_400(data="{} value is missing".format( key ))
        return values



    def require_unique(self, values:any, name:str="Value") -> None:

        if isinstance(values, list) and len(values) >= 1:
            self.send_response_400(data="{} already exists".format( name ))

        elif isinstance(values, dict) and len(values.keys()) >= 1:
            self.send_response_400(data="{} already exists".format( name ))

        else:
            return


    def require_exists(self, values:any, name:str="Value") -> None:

        if values is None:
            self.send_response_400(data="{} does not exist in the database".format( name ))

        if isinstance(values, list) and values == []:
            self.send_response_400(data="{} does not exist in the database".format( name ))

        elif isinstance(values, dict) and values == {}:
            self.send_response_400(data="{} does not exist in the database".format( name ))
        else:
            return

    def post_values(self):
        data = json_decode( self.request.body )
        return data


    def set_ACAO_header(self, sites="*"):
#        print('setting ACAO headers')
        self.set_header("Access-Control-Allow-Origin", sites)
        self.set_header("Access-Control-Allow-Headers", "x-requested-with, content-type,authorization")
#        self.set_header("Access-Control-Allow-Headers", "*")

        self.set_header('Access-Control-Allow-Methods', 'POST, GET, OPTIONS, PATCH, DELETE')


    def set_json_header(self):
         """Set the default response header to be JSON."""
         self.set_header("Content-Type", 'application/json; charset="utf-8"')


    def allow_options(self):
        if environment == 'development':
            self.set_ACAO_header()
        self.set_status(204)
        self.finish()


    # Success
    def send_response(self, data=None, status=200):
        """Construct and send a JSON response with appropriate status code."""

        if token is not None:
            self.set_auth_token( token )

        self.set_status(status)

        if environment == 'development':
            self.set_ACAO_header()

        # check if the data is already in valid json format, otherwise make it
        try:
            json_object = json.loads( data )
        except TypeError as e:
            data = json.dumps(data, cls=UUIDEncoder)

        self.finish( data  )


    def send_status_code(self, status:int):
        """Construct and send an empty response with appropriate status code."""

        self.set_status(status)
        return self.finish( )

    def send_file(self, file_name: str, file_path: str) -> None:
        if environment == 'development':
            self.set_ACAO_header()

        buf_size = 4096
        self.set_header('Content-Type', 'application/octet-stream; charset=utf-8')
        self.set_header('Content-Disposition',
                       "attachment; filename*=utf-8''{}".format(urllib.parse.quote(file_name, 'utf-8')))
        self.set_header("Access-Control-Expose-Headers", "Content-Disposition")

        with open(file_path, 'rb') as f:
            while True:
                data = f.read(buf_size)
                if not data:
                    break
                self.write(data)

        self.finish()


    # Success
    def send_response_200(self):
        return self.send_response( data=None, status=200)

    # Created
    def send_response_201(self):
        return self.send_response( data=None, status=201)

    # Accecpted
    def send_response_202(self, data):
        return self.send_status_code( status=202)

    # No content
    def send_response_204(self):
        return self.send_status_code( status=204)


    def raise_error(self, status:int, msgs:any=None):
        self.send_error(status_code=status, msgs=msgs)
        raise HTTPError


    def write_error(self, status_code:int=500, msgs:any=None, **kwargs) -> None:
        if isinstance(msgs, str):
            msgs = [msgs]


        data = {'msgs': msgs}
        try:
            data = json.loads( data )
        except TypeError:
            data = json.dumps(data, cls=UUIDEncoder)

        self.set_header("Content-Type", 'application/json; charset="utf-8"')
        self.write( data )
        self.finish()


            # bad request
    def send_response_400(self, data:any=None):
#        pp.pprint( data )
        self.raise_error(status=400, msgs=data)

    # Unauthorized
    def send_response_401(self, data:any=None):
        self.raise_error(status=401, msgs=data)

    # Forbidden
    def send_response_403(self, data:any=None):
        self.raise_error(status=403, msgs=data)
#        return self.send_response( data=data, status=403)

    # Not fund
    def send_response_404(self):
        self.raise_error(status=404)
#        return self.send_response(status=404)

    # Internal Server Error
    def send_response_500(self, data:any=None):
        self.raise_error(status=500, msgs=data)
#        return self.send_response( data=data, status=500)

    # Not Implemented
    def send_response_501(self, data:any=None):
        self.raise_error(status=501, msgs=data)
#        return self.send_response( data=data, status=501)

    # Service Unavailable
    def send_response_503(self, data:any=None):
        self.raise_error(status=503, msgs=data)
#        return self.send_response( data=data, status=503)


    def set_auth_token(self, token):
        self.set_header("Authorization", f"Bearer {token}")


    def access_token(self):
        c_token = None
        auth_header = self.request.headers.get('Authorization', None)
#        print("Auth header: {}".format( auth_header ))
        if auth_header:
            c_token = auth_header[7:]

        if c_token is None:
            self.send_response_401( )

        return c_token



    def check_token(self, tokens:list=None):
        global token
        header_token = None
        auth_header = self.request.headers.get('Authorization', None)
#        print("Auth header: {}".format( auth_header ))
        if auth_header:
            header_token = auth_header[7:]

#        logger.debug( f"Header Token: {header_token}")

        valid_token = False
        if tokens is not None and header_token in tokens:
            valid_token = True

        if token is not None and header_token == token:
            valid_token = True


        if not valid_token:
            logger.debug(f"'{header_token}' token is not valid  ==> main: '{token}' OR proxy: {tokens}")
            self.send_response_401( )

        return token


    def valid_token(self) -> bool:

        access_token = self.access_token()

        token_data = introspection_func( access_token )
        if 'active' not in token_data or token_data['active'] is not True:
            self.send_response_401( data="Token not active" )

        return token_data




    def userprofile( self ) -> dict:

        token = self.access_token()


        if token not in token_cache:
            token_data = self.valid_token(  )
            if 'active' not in token_data or token_data['active'] is not True:
                self.send_response_401( data="Token not active" )

            user_id = token_data[ 'data' ]['user_id']
            token_cache[ token ] = userprofile_func( user_id )

        return token_cache[ token ]



def json_decode(value):

    return tornado.escape.json_decode( value )

def url_unescape(uri:str) -> str:
    if uri is None:
        return uri
    
    return tornado.escape.url_unescape( uri )


def url_escape(uri:str, plus=True) -> str:
    if uri is None:
        return uri
    
    return tornado.escape.url_escape( uri, plus=plus )


def set_token(new_token:str):
    global token
    token = new_token


def run_app(urls, port=8888, **kwargs):

    app = Application(urls, **kwargs)
    app.listen(port)
    IOLoop.current().start()



def development():
    global environment 
    environment = 'development'
