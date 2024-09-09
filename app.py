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
from datetime import datetime, timezone, timedelta

from models import initialize_api_models
from classes import db, User, Event, CategoryTable, TokenBlocklist

load_dotenv()

app = Flask(__name__)
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY')
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=4)
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('SQLALCHEMY_DATABASE_URI')
db.init_app(app)

jwt = JWTManager(app)
api = Api(app)
bcrypt = Bcrypt(app)
cors = CORS(app)

# Initialize API models
models = initialize_api_models(api)
signup_and_login_model = models['signup_and_login_model']
events_model = models['events_model']
events_update_model = models['events_update_model']
events_delete_model = models['events_delete_model']
category_put_model = models['category_put_model']
category_delete_model = models['category_delete_model']
category_color_change_model = models['category_color_change_model']

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
                        'category_id': event.category_id,
                        'location': event.location
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
        required_fields = ['title', 'body', 'start_time', 'end_time', 'status', 'categoryName']
        missing_fields = [field for field in required_fields if not data.get(field)]
        if missing_fields:
            return {'error': f'Missing fields: {", ".join(missing_fields)}'}, 400

        

        try:
            current_user_email = get_jwt_identity()
            user = User.query.filter_by(email=current_user_email).first()
            if not user:
                return {'error': 'User not found'}, 404
            
            # check if category already exists
            category = CategoryTable.query.filter_by(name=data['categoryName'], user_id=user.id).first()

            # category_id = 0

            if category:
                category_id = category.id
            else:
                new_category = CategoryTable(
                    name=data['categoryName'],
                    user_id= user.id,
                    color=data['categoryColor'],
                )
                db.session.add(new_category)
                db.session.flush()
                category_id = new_category.id


            new_event = Event(
                title=data['title'],
                body=data['body'],
                user_id=user.id,
                start_time=data['start_time'],
                end_time=data['end_time'],
                status=data['status'],
                category_id=category_id,
                location=data['location']
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

            # check if category already exists
            category = CategoryTable.query.filter_by(name=data['categoryName'], user_id=user.id).first()

            old_category_id = event.category_id

            if category:
                event.category_id = category.id
            else:
                new_category = CategoryTable(
                    name=data['categoryName'],
                    user_id= user.id,
                    color=data['categoryColor'],
                )
                db.session.add(new_category)
                db.session.flush()
                event.category_id = new_category.id
            
            # update the event
            event.title = data['title']
            event.body = data['body']
            event.start_time = data['start_time']
            event.end_time = data['end_time']
            event.status = data['status']
            event.location = data['location']
            db.session.flush()
            
            # delete the category if there are no more events
            remaining_events = Event.query.filter_by(category_id=old_category_id, user_id=user.id).first()
            if not remaining_events:
                # delete the category
                category = CategoryTable.query.filter_by(id=old_category_id, user_id=user.id).first()
                db.session.delete(category)

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
            
            category_id = event.category_id
            
            db.session.delete(event)
            db.session.flush()

            # delete the category if there are no more events
            remaining_events = Event.query.filter_by(category_id=category_id, user_id=user.id).first()

            if not remaining_events:
                # delete the category
                category = CategoryTable.query.filter_by(id=category_id, user_id=user.id).first()
                db.session.delete(category)

            db.session.commit()
            return {'message': 'Event was successfully deleted!'}, 200
        except Exception as e:
            return {'error': str(e)}, 500


# Category routes
@category_ns.route('/')
class Category(Resource):
    @jwt_required()
    def get(self):
        try:
            current_user_email = get_jwt_identity()
            user = User.query.filter_by(email=current_user_email).first()
            if not user:
                return {'error': 'User not found'}, 404

            categories = CategoryTable.query.filter_by(user_id=user.id).all()

            if categories:
                category_list = [
                    {
                        'category_id': category.id,
                        'name': category.name,
                        'color': category.color
                    }
                    for category in categories
                ]

                return {'category_list': category_list}, 200
            else:
                return {'category_list': []}, 200
        except Exception as e:
            return {'error': str(e)}, 500

    @jwt_required()
    @category_ns.expect(category_put_model)
    def put(self):
        data = request.json

        try:
            current_user_email = get_jwt_identity()
            user = User.query.filter_by(email=current_user_email).first()
            if not user:
                return {'error': 'User not found'}, 404

            category_to_update = CategoryTable.query.filter_by(id=data['id'], user_id=user.id).first()
            category_to_update.name = data['new_name']

            db.session.commit()
            return {'message': 'Category name was successfully changed!'}, 200
        except Exception as e:
            db.session.rollback()
            return {'error': str(e)}, 500

    @jwt_required()
    @category_ns.expect(category_delete_model)
    def delete(self):
        data = request.json

        try:
            current_user_email = get_jwt_identity()
            user = User.query.filter_by(email=current_user_email).first()
            if not user:
                return {'error': 'User not found'}, 404

            events_to_delete = Event.query.filter_by(user_id=user.id, category_id=data['id']).all()
            # if not events_to_delete:
            #     return {'error', 'No events found with the specified category'}, 404

            if events_to_delete:
                for event in events_to_delete:
                    db.session.delete(event)
            
            category_to_delete = CategoryTable.query.filter_by(user_id=user.id, id=data['id']).first()

            if category_to_delete:
                db.session.delete(category_to_delete)
            

            db.session.commit()
            return {'message': 'Category was successfully deleted!'}, 200
        except Exception as e:
            db.session.rollback()
            return {'error': str(e)}, 500

@category_ns.route('/color')
class CatgoryColor(Resource):
    @jwt_required()
    @category_ns.expect(category_color_change_model)
    def put(self):
        data = request.json

        try:
            current_user_email = get_jwt_identity()
            user = User.query.filter_by(email=current_user_email).first()
            if not user:
                return {'error': 'User not found'}, 404
            
            category = CategoryTable.query.filter_by(id=data['id'], user_id=user.id).first()

            if not category:
                return {'error': 'Category not found'}, 404
            
            category.color = data['new_color']
            db.session.commit()

            return {'message': 'Category color was successfully changed!'}, 200
        except Exception as e:
            db.session.rollback()
            return {'error': str(e)}, 500
        

if __name__ == '__main__':
    app.run(debug=True)