from flask import Flask, request
from flask_restx import Api, Resource, fields
from flask_bcrypt import Bcrypt
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import (
    create_access_token,
    get_jwt,
    get_jwt_identity,
    jwt_required,
    JWTManager
)
import os
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('SQLALCHEMY_DATABASE_URI')
db = SQLAlchemy(app)

jwt = JWTManager(app)
api = Api(app)
bcrypt = Bcrypt(app)
cors = CORS(app, resources={r"/*": {"origins": "http://localhost:5173"}}) # Add link to env after

signup_and_login_model = api.model('SignUp', {
    'email': fields.String(required=True, description='User email'),
    'password': fields.String(required=True, description='User password')
})

events_model = api.model('Event', {
    'title': fields.String(required=True, description='Event title'),
    'body': fields.String(required=True, description='Event description'),
    'start_time': fields.DateTime(required=True, description='Event start time', example='2024-06-01T10:00:00'),
    'end_time': fields.DateTime(required=True, description='Event end time', example='2024-06-01T11:00:00'),
    'status': fields.String(required=True, description='Event status'),
    'category': fields.String(required=True)
})

events_update_model = api.model('Update event', {
    'id': fields.Integer(required=True, description='Event id'),
    'title': fields.String(required=True, description='Event title'),
    'body': fields.String(required=True, description='Event description'),
    'start_time': fields.DateTime(required=True, description='Event start time', example='2024-06-01T10:00:00'),
    'end_time': fields.DateTime(required=True, description='Event end time', example='2024-06-01T11:00:00'),
    'status': fields.String(required=True, description='Event status'),
    'category': fields.String(required=True)
})

events_delete_model = api.model('Delete event', {
    'id': fields.Integer(required=True, description='Event id')
})

auth_ns = api.namespace('auth', description='Authentication operations')
event_ns = api.namespace('events', description='Event operations')

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    email = db.Column(db.String(50), nullable=False, unique=True)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=db.func.current_timestamp())

class Event(db.Model):
    __tablename__ = 'events'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    title = db.Column(db.String(100), nullable=False)
    body = db.Column(db.Text)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    start_time = db.Column(db.DateTime, nullable=False)
    end_time = db.Column(db.DateTime, nullable=False)
    status = db.Column(db.String(50))
    category = db.Column(db.String(50))

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

if __name__ == '__main__':
    app.run(debug=True)