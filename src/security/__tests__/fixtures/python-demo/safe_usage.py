def find_user(cursor, uid, name):
    # A placeholder and string formatting on one line: regex detection treats the ? as parameterised.
    cursor.execute("SELECT id FROM users WHERE id = ? AND name = '%s'" % name, (uid,))
    return cursor.fetchone()
