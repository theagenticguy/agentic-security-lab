"""Order lookup endpoint. This SQLi variant was NEVER fixed -- the hunter should find it."""


def get_order(cursor, oid):
    # Variant of the users.py SQLi: untrusted id interpolated into the query string.
    cursor.execute(f"SELECT * FROM orders WHERE id = {oid}")
    return cursor.fetchone()
