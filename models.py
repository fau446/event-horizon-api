from flask_restx import fields

def initialize_api_models(api):
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

    category_model = api.model('Category', {
        'old_name': fields.String(required=True, description='Old category name'),
        'new_name': fields.String(required=True, description='New category name')
    })

    category_delete_model = api.model('Delete category', {
        'name': fields.String(required=True, description='Category name')
    })

    return {
        'signup_and_login_model': signup_and_login_model,
        'events_model': events_model,
        'events_update_model': events_update_model,
        'events_delete_model': events_delete_model,
        'category_model': category_model,
        'category_delete_model': category_delete_model
    }
