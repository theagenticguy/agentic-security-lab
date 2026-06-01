"""User lookup endpoint. The SQLi here was the seed bug that got fixed."""


def get_user(cursor, name):
    # Fixed: parameterized query (was an f-string SQLi).
    cursor.execute("SELECT * FROM users WHERE name = ?", (name,))
    return cursor.fetchone()
