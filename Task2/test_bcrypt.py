import bcrypt

password = b'super secret password'
hashed = bcrypt.hashpw(password, bcrypt.gensalt())
print(type(hashed))
if bcrypt.checkpw(password, hashed):
    print('It matches!')
else:
    print('It does not Match')

