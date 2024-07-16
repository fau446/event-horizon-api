from flask import Flask, request
from flask_restx import Api, Resource, fields
from flask_bcrypt import Bcrypt
from flask_cors import CORS
from sqlalchemy.sql import func
from flask_jwt_extended import (
    create_access_token,
    get_jwt,
    get_jwt_identity,
    jwt_required,
    JWTManager
)
import os
from dotenv import load_dotenv
from datetime import datetime, timezone

from models import initialize_api_models
from classes import db, User, Event, TokenBlocklist

load_dotenv()

app = Flask(__name__)
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('SQLALCHEMY_DATABASE_URI')
db.init_app(app)

jwt = JWTManager(app)
api = Api(app)
bcrypt = Bcrypt(app)
cors = CORS(app, resources={r"/*": {"origins": "http://localhost:5173"}}) # Add link to env after

# Initialize API models
models = initialize_api_models(api)
signup_and_login_model = models['signup_and_login_model']
events_model = models['events_model']
events_update_model = models['events_update_model']
events_delete_model = models['events_delete_model']
category_model = models['category_model']

auth_ns = api.namespace('auth', description='Authentication operations')
event_ns = api.namespace('events', description='Event operations')
category_ns = api.namespace('category', description='Category operations')

@jwt.token_in_blocklist_loader
def check_if_token_revoked(jwt_header, jwt_payload: dict) -> bool:
    jti = jwt_payload["jti"]
    token = db.session.query(TokenBlocklist.id).filter_by(jti=jti).scalar()

    return token is not None


# Auth Routes
@auth_ns.route('/sign_up')
class SignUp(Resource):
    @auth_ns.expect(signup_and_login_model)
    def post(self):
        data = request.json
        pw_hash = bcrypt.generate_password_hash(data['password']).decode('utf-8')

        try:
            existing_user = User.query.filter_by(email=data['email']).first()
            if existing_user:
                return {'error': 'User already exists, please login with your email and password.'}, 401
            
            # create new user
            new_user = User(email=data['email'], password_hash=pw_hash)
            db.session.add(new_user)
            db.session.commit()

            access_token = create_access_token(identity=data['email'])
            return {'message': 'Sign up successful!', 'access_token': access_token}, 200
        except Exception as e:
            db.session.rollback()
            return {'error': 'Sign up failed', 'message': str(e)}, 500

@auth_ns.route('/login')
class Login(Resource):
    @auth_ns.expect(signup_and_login_model)
    def post(self):
        data = request.json

        try:
            user = User.query.filter_by(email=data['email']).first()

            if user and bcrypt.check_password_hash(user.password_hash, data['password']):
                access_token = create_access_token(identity=user.email)
                return {'message': 'Login Successful!', 'access_token': access_token}, 200
            else:
                return {'error': 'Wrong email or password, please try again!'}, 401
        except Exception as e:
            return {'error': str(e)}, 500

@auth_ns.route('/check_authentication')
class CheckLogin(Resource):
    @jwt_required()
    def get(self):
        try:
            current_user_email = get_jwt_identity()
            user = User.query.filter_by(email=current_user_email).first()
            if not user:
                return {'error': 'User not found'}, 404
            else:
                return {'message':'Authentication successful!' ,'logged_in_as': current_user_email}, 200
        except Exception as e:
            return {'error': f'Authentication failed: {str(e)}'}, 500

@auth_ns.route('/logout')
class Logout(Resource):
    @jwt_required(verify_type=False)
    def post(self):
        try:
            current_user_email = get_jwt_identity()
            user = User.query.filter_by(email=current_user_email).first()

            token = get_jwt()
            jti = token['jti']
            ttype = token['type']
            now = datetime.now(timezone.utc)
            db.session.add(TokenBlocklist(jti=jti, type=ttype, user_id=user.id, created_at=now))
            db.session.commit()
            
            return {'message': 'Logout success!'}, 200
        except Exception as e:
            db.session.rollback()
            return {'error': str(e)}, 500


# Event routes
@event_ns.route('/')
class Events(Resource):
    @jwt_required()
    def get(self):
        try:
            current_user_email = get_jwt_identity()
            user = User.query.filter_by(email=current_user_email).first()

            if not user:
                return {'error': 'User not found'}, 404
            
            events = Event.query.filter_by(user_id=user.id).all()

            if events:
                events_list = [
                    {
                        'id': event.id,
                        'title': event.title,
                        'body': event.body,
                        'start_time': event.start_time.isoformat(),
                        'end_time': event.end_time.isoformat(),
                        'status': event.status,
                        'category': event.category
                    }
                    for event in events
                ]

                return {'events_list': events_list}, 200
            else:
                return {'events_list': []}, 200
        except Exception as e:
            return {'error': str(e)}, 500

    @jwt_required()
    @event_ns.expect(events_model)
    def post(self):
        data = request.json

        # check if data contains fields that are empty
        required_fields = ['title', 'body', 'start_time', 'end_time', 'status', 'category']
        missing_fields = [field for field in required_fields if not data.get(field)]
        if missing_fields:
            return {'error': f'Missing fields: {", ".join(missing_fields)}'}, 400

        

        try:
            current_user_email = get_jwt_identity()
            user = User.query.filter_by(email=current_user_email).first()
            if not user:
                return {'error': 'User not found'}, 404
            
            new_event = Event(
                title=data['title'],
                body=data['body'],
                user_id=user.id,
                start_time=data['start_time'],
                end_time=data['end_time'],
                status=data['status'],
                category=data['category']
            )
            db.session.add(new_event)
            db.session.commit()

            return {'message': 'Event creation successful'}, 201
        except Exception as e:
            db.session.rollback()
            return {'error': str(e)}, 500
        
    @jwt_required()
    @event_ns.expect(events_update_model)
    def put(self):
        data = request.json

        try:
            current_user_email = get_jwt_identity()
            user = User.query.filter_by(email=current_user_email).first()
            if not user:
                return {'error': 'User not found'}, 404
            
            # check if the event exists and belongs to the user
            event = Event.query.filter_by(id=data['id']).first()
            if not event:
                return {'error': 'Event not found'}, 404
            elif event.user_id != user.id:
                return {'error': 'Unauthorized'}, 403
            
            # update the event
            event.title = data['title']
            event.body = data['body']
            event.start_time = data['start_time']
            event.end_time = data['end_time']
            event.status = data['status']
            event.category = data['category']

            db.session.commit()
            return {'message': 'Event was successfully edited!'}, 200
        except Exception as e:
            db.session.rollback()
            return {'error': str(e)}, 500
        
    @jwt_required()
    @event_ns.expect(events_delete_model)
    def delete(self):
        data = request.json

        try:
            current_user_email = get_jwt_identity()
            user = User.query.filter_by(email=current_user_email).first()
            if not user:
                return {'error': 'User not found'}, 404
            
            # check if the event exists and belongs to the user
            event = Event.query.filter_by(id=data['id']).first()
            if not event:
                return {'error': 'Event not found'}, 404
            elif event.user_id != user.id:
                return {'error': 'Unauthorized'}, 403
            
            # delete the event
            db.session.delete(event)
            db.session.commit()
            return {'message': 'Event was successfully deleted!'}, 200
        except Exception as e:
            return {'error': str(e)}, 500


# Category routes
@category_ns.route('/')
class Category(Resource):
    @jwt_required()
    @category_ns.expect(category_model)
    def put(self):
        data = request.json

        try:
            current_user_email = get_jwt_identity()
            user = User.query.filter_by(email=current_user_email).first()
            if not user:
                return {'error': 'User not found'}, 404
        
            events_to_update = Event.query.filter_by(user_id=user.id, category=data['old_name']).all()
            if not events_to_update:
                return {'error', 'No events found with the specified category!'}, 404

            for event in events_to_update:
                event.category = data['new_name'] 

            db.session.commit()
            return {'message': 'Category name was successfully changed!'}, 200
        except Exception as e:
            db.session.rollback()
            return {'error': str(e)}, 500

if __name__ == '__main__':
    app.run(debug=True)