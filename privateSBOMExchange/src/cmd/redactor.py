from src.lib import redactor 
from flask import Flask, request, make_response, jsonify
from cryptography import x509

# we keep this in memory, seems to hold some global variables that we may need
# to use.

app = Flask(__name__)

@app.route("/")
def hello_world():
    return "<p>Petra: this is a JSON api, you shouldn't be looking here!</p>"

"""
    enroll receives an object containing only cert, and returns a success/fail
    symbol depending on how things went.


"""
@app.route("/enroll", methods=['POST'])
def enroll():
    data = request.get_json()
    if 'cert' not in data:
        # This error handling could be done better
        raise Exception("request is malformed!")
    cert = x509.load_pem_x509_certificate(bytes(data['cert'].encode('ascii')))

    current_role = redactor.EnrollRoles(cert)

    response_data = {"status": "ok",
                     "current_role": current_role}
    
    return make_response(jsonify(response_data), 200)



if __name__ == "__main__":
    print("running redactor...")
    app.run(debug=True)
