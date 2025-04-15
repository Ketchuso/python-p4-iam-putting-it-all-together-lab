#!/usr/bin/env python3

from flask import request, session, jsonify, make_response
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError
import traceback

from config import app, db, api
from models import User, Recipe

class Signup(Resource):
    def post(self):
        data = request.get_json()

        username = data.get('username')
        password = data.get('password')
        image_url = data.get('image_url')
        bio = data.get('bio')

        if not username or not password:
            return {"error": "Username and password are required"}, 422
        
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            return {"error": "username already exists"}, 409
        
        try:
            new_user = User(
                username = username,
                image_url = image_url,
                bio = bio
            )
            new_user.password_hash = password

            db.session.add(new_user)
            db.session.commit()

            return new_user.to_dict(), 201

        except Exception as e:
            traceback.print_exc()
            return {"error": str(e)}, 500

class CheckSession(Resource):
    def get(self):
        user_id = session.get('user_id')

        if user_id:
            user = db.session.get(User, user_id)

            if user:
                return {
                    "id": user.id,
                    "username": user.username,
                    "image_url": user.image_url,
                    "bio": user.bio
                }, 200
        
        else:
            return {"error": "Unauthorized"}, 401

class Login(Resource):
    def post(self):
        data = request.get_json()
        user = db.session.query(User).filter(User.username == data['username']).first()
        password = data['password']
        if user and user.authenticate(password):
            session["user_id"] = user.id
            return {
                "id": user.id,
                    "username": user.username,
                    "image_url": user.image_url,
                    "bio": user.bio
            }, 200
        else:
            return {
                "error": "invalid username or password"
            }, 401

class Logout(Resource):
    def delete(self):
        user = db.session.query(User).filter(User.id == session.get('user_id')).first()
        if user:
            session['user_id'] = None
            return make_response("", 204)
        else:
            return {
                "error": "unauthorized"
            }, 401

class RecipeIndex(Resource):
    def get(self):
        user = db.session.query(User).filter(User.id == session.get('user_id')).first()
        if user:
            return [recipe.to_dict() for recipe in user.recipes], 200
        else:
            return {
                "error": "unauthorized"
            }, 401
        
    def post(self):
        user_id = session.get('user_id')
        if not user_id:
            return { "error": "Unauthorized" }, 401

        data = request.get_json()
        title = data.get('title')
        instructions = data.get('instructions')
        minutes_to_complete = data.get('minutes_to_complete')

        if len(instructions) < 50:
            return {
                "error": "instructions must be 50 characters or longer"
            }, 422

        new_recipe = Recipe(
            title=title,
            instructions=instructions,
            minutes_to_complete=minutes_to_complete,
            user_id=user_id
        )

        db.session.add(new_recipe)
        db.session.commit()

        return new_recipe.to_dict(), 201


api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')
api.add_resource(RecipeIndex, '/recipes', endpoint='recipes')


if __name__ == '__main__':
    app.run(port=5555, debug=True)