from flask import Flask, request
from flask_restx import Api, Resource, fields
from flask_bcrypt import Bcrypt
from flask_cors import CORS
import sqlite3
from flask_jwt_extended import create_access_token
from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended import jwt_required
from flask_jwt_extended import JWTManager


app = Flask(__name__)
app.config['JWT_SECRET_KEY'] = 'super-secret' # Change this after
jwt = JWTManager(app)
api = Api(app)
bcrypt = Bcrypt(app)
cors = CORS(app, resources={r"/*": {"origins": "http://localhost:5173"}}) # Add link to env after

signup_and_login_model = api.model('SignUp', {
    'email': fields.String(required=True, description='User email'),
    'password': fields.String(required=True, description='User password')
})


auth_ns = api.namespace('auth', description='Authentication operations')

@auth_ns.route('/sign_up')
class SignUp(Resource):
    @auth_ns.expect(signup_and_login_model)
    def post(self):
        data = request.json
        pw_hash = bcrypt.generate_password_hash(data['password']).decode('utf-8')

        try:
            with sqlite3.connect('database.db') as con:
                cur = con.cursor()

                # check if the user already exists
                cur.execute('''
                    SELECT *
                    FROM users
                    WHERE email = ?
                ''', (data['email'],))
                user = cur.fetchone()
                if user:
                    return {'error': 'User already exists'}, 401

                cur.execute('''
                    INSERT INTO users
                            (email, password_hash)
                            VALUES (?, ?)
                            ''', (data['email'], pw_hash))
                con.commit()

                access_token = create_access_token(identity=data['email'])
                return {'message': 'Sign up successful', 'access_token': access_token}, 200
        except:
            con.rollback()
            return {'error': 'Sign up failed'}, 500
        finally:
            con.close()

@auth_ns.route('/login')
class Login(Resource):
    @auth_ns.expect(signup_and_login_model)
    def post(self):
        data = request.json

        try:
            with sqlite3.connect('database.db') as con:
                con.row_factory = sqlite3.Row

                cur = con.cursor()
                # find the user
                cur.execute('''
                    SELECT *
                    FROM users
                    WHERE email = ?
                ''', (data['email'],))

                user = cur.fetchone()

                if user and bcrypt.check_password_hash(user['password_hash'], data['password']):
                    access_token = create_access_token(identity=user['email'])
                    return {'message': 'Login Successful', 'access_token': access_token}, 200
                else:
                    return {'error': 'Wrong email or password'}, 401
        except:
            return {'error': 'Error has occurred'}, 500
        finally:
            con.close()

@auth_ns.route('/check_authentication')
class CheckLogin(Resource):
    @jwt_required()
    def get(self):
        current_user_email = get_jwt_identity()

        try:
            with sqlite3.connect('database.db') as con:
                con.row_factory = sqlite3.Row

                cur = con.cursor()
                # find user_id
                cur.execute('''
                    SELECT id
                    FROM users
                    WHERE email = ?
                            ''', (current_user_email,))
                user = cur.fetchone()

                if user:
                    return {'logged_in_as': current_user_email, 'user_id': user['id']}, 200
                else:
                    return {'error': 'User not found'}, 404
        except:
            return {'error': 'Error has occurred'}, 500
        finally:
            con.close()

if __name__ == '__main__':
    app.run(debug=True)