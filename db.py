import psycopg2
from psycopg2 import OperationalError, IntegrityError
from werkzeug.security import generate_password_hash, check_password_hash

class Database:
    def __init__(self, dsn):
        try:
            self.conn = psycopg2.connect(dsn)
            self.conn.autocommit = True
        except OperationalError as e:
            print(f"Error connecting to database: {e}")
            raise

    def _get_cursor(self):
        try:
            return self.conn.cursor()
        except OperationalError:
            print("Error creating database cursor.")
            raise


    def register_user(self, username, password):
        try:
            hashed_password = generate_password_hash(password)
            with self._get_cursor() as cursor:
                cursor.execute(
                    'INSERT INTO users (username, password) VALUES (%s, %s)',
                    (username, hashed_password)
                )
            return True
        except IntegrityError:
            return False
        except Exception as e:
            print("Error registering user:", e)
            return False

    def login_user(self, username, password):
        with self._get_cursor() as cursor:
            cursor.execute('SELECT id, username, role, password FROM users WHERE username = %s', (username,))
            user = cursor.fetchone()
        if user and check_password_hash(user[3], password):
            return user
        return None

    def add_note(self, user_id, content):
        with self._get_cursor() as cursor:
            cursor.execute('INSERT INTO notes (user_id, content) VALUES (%s, %s)', (user_id, content))

    def get_user_notes(self, user_id):
        with self._get_cursor() as cursor:
            cursor.execute('SELECT id, content, created_at FROM notes WHERE user_id = %s ORDER BY created_at DESC', (user_id,))
            return cursor.fetchall()


    def add_post(self, user_id, title, content):
        with self._get_cursor() as cursor:
            cursor.execute('INSERT INTO posts (user_id, title, content) VALUES (%s, %s, %s)', (user_id, title, content))


    def get_all_posts(self, include_hidden=False):
        if include_hidden:
            query = (
                'SELECT posts.id, posts.user_id, users.username, posts.title, posts.content, posts.created_at, posts.visible '
                'FROM posts JOIN users ON posts.user_id = users.id '
                'ORDER BY posts.created_at DESC'
            )
            params = ()
        else:
            query = (
                'SELECT posts.id, posts.user_id, users.username, posts.title, posts.content, posts.created_at, posts.visible '
                'FROM posts JOIN users ON posts.user_id = users.id '
                'WHERE posts.visible = TRUE '
                'ORDER BY posts.created_at DESC'
            )
            params = ()
        with self._get_cursor() as cursor:
            cursor.execute(query, params)
            return cursor.fetchall()




    def set_post_visibility(self, post_id, visibility, user_role):
        if user_role != 'admin':
            raise PermissionError("Only admin can set visibility")
        with self._get_cursor() as cursor:
            cursor.execute('UPDATE posts SET visible = %s WHERE id = %s', (visibility, post_id))



    def delete_post(self, post_id):
        with self._get_cursor() as cursor:
            cursor.execute('DELETE FROM posts WHERE id = %s', (post_id,))

    def delete_note(self, note_id):
        with self._get_cursor() as cursor:
            cursor.execute('DELETE FROM notes WHERE id = %s', (note_id,))

    def is_post_owner(self, user_id, post_id, user_role):
        if user_role == 'admin':
            return True
        with self._get_cursor() as cursor:
            cursor.execute('SELECT user_id FROM posts WHERE id = %s', (post_id,))
            post_owner = cursor.fetchone()
        return post_owner and post_owner[0] == user_id

    def is_note_owner(self, user_id, note_id):
        with self._get_cursor() as cursor:
            cursor.execute('SELECT user_id FROM notes WHERE id = %s', (note_id,))
            note_owner = cursor.fetchone()
        return note_owner and note_owner[0] == user_id

    def __del__(self):
        self.conn.close()