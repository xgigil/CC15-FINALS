Role-specific passwords:
Executive: EXEC_PASS
Member: MEM_PASS

Dummy account credentials:
username, password: bgil, bgil
username, password: bloi, bloi


Admin credentials:
username: admin
password: gailangadmin@123


TO DO:
Overall:
1. Any deletion is still not working (ang ako na figure out ra nga method is soft deleting, meaning dili mawala sa database ang account pero dili lang siya ma gamit for login)
2. Deletion Request buttons dont work for both admin and executive

Admin:
1. View system logs fails.
2. Edit button needs rework in manage users. Not clear which row it is editing.
3. Should not be able to edit self in manage users.

Executive:
1. If they have made a deletion request, their username should not appear in their deletion requests table
2. add view inactive users
3. manage user profile should have search function. and be put in main area


BUGS:
1. Editing own username in manage users (should not be allowed), bug.
2. Manage users in general is a bug fest.
3. When approving deletion, it says request no longer valid
4. Tables should not be clickable.

Cursor questions nga wala pa nako na ask:
1. could you, edit the def approve_registration so that everytime it approves the account deletion, the account details are deleted from the database. make sure also that the account delection rejection function works by rejecting the deletion.
2. Add logging for these deletion operations. (not sure if should ask)
3. Add the ability to restore recently deleted accounts. (not sure if should ask)


