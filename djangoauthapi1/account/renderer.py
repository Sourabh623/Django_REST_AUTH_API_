from rest_framework.renderers import JSONRenderer
import json

class UserRenderer(JSONRenderer):
    charset = 'utf-8'

    #defind the render method
    def render(self, data, accepted_media_type=None, renderer_context=None):
        #make a res variable
        response = ""
        
        #data and error converted into json
        if "ErrorDetail" in str(data):
            response = json.dumps({'errors':data})
        else:
            response = json.dumps(data)

        #error send to the client
        return response
