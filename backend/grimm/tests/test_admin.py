import os
import json
import bcrypt
import unittest
from unittest import mock
os.environ['FLASK_ENV'] = 'dev'

from grimm import db
from grimm.utils import constants
from grimm.models.admin import Admin

from .base import post_json, AdminCase

class TestAdminCreate(AdminCase):
    @mock.patch('grimm.utils.emailverify.EmailVerifyToken.send_email')
    def test_normal(self, mocked_func):
        mocked_func.return_value = True

        admin_info = {
            'email': 'test@exmaple.com',
            'password': 'A!%123test',
            'name': 'new_admin'
        }
        res = post_json(self.client, '/admin', admin_info)

        data = json.loads(res.data)
        self.assertEqual(data["status"], "success")

        with self.app.app_context():
            ad = db.session.query(Admin).filter_by(email=admin_info['email']).first()
            self.assertEqual(ad.name, admin_info['name'])

    def test_duplicated(self):
        res = post_json(self.client, '/admin', {
                'email': self.default_admin_attrs['email'],
                'password': 'AnotherStrongPassword123!',
                'name': 'admin'
            }, headers={})
        self.assertEqual(res.status_code, 200)
        data = json.loads(res.data)
        self.assertEqual(data["status"], "failure")
        self.assertEqual(data["message"], "已注册邮箱")

    def test_weak_password(self):
        # Trying to create an admin with a weak password
        res = post_json(self.client, '/admin', {
                'email': 'anothernewemail@test.com',
                'password': 'weak',
                'name': 'weakadmin'
            }, headers={})
        self.assertEqual(res.status_code, 200)
        data = json.loads(res.data)
        self.assertEqual(data["status"], "failure")
        self.assertEqual(data["message"], "密码不合规范")

class TestAdminLogin(AdminCase):
    def test_login_success(self):
        res = post_json(self.client, '/login', {
                'email': self.default_admin_attrs['email'],
                'password': self.default_admin_attrs['password'],
            })
        self.assertEqual(res.status_code, 200)
        data = json.loads(res.data)
        self.assertEqual(data["status"], "success")

    def test_login_fail(self):
        res = post_json(self.client, '/login', {
                'email': self.default_admin_attrs['email'],
                'password': self.default_admin_attrs['password'] + 'a',
            })
        self.assertEqual(res.status_code, 403)

class TestAdminQuery(AdminCase):
    def test_get_admins(self):
        # Assuming there are admins in the database
        res = self.client.get('/admins', headers={})
        self.assertEqual(res.status_code, 200)
        data = json.loads(res.data)
        self.assertTrue(len(data) > 0)
        # Check the structure of the response
        for admin in data:
            self.assertIn("id", admin)
            self.assertIn("email", admin)
            self.assertIn("type", admin)
            self.assertIn("name", admin)
            self.assertIn("email_verified", admin)

    def test_get_admin(self):
        # Assuming there is an admin with id 2
        res = self.client.get('/admin/2', headers={})
        self.assertEqual(res.status_code, 200)
        data = json.loads(res.data)
        self.assertEqual(data["status"], "success")
        self.assertEqual(data["id"], 2)
        self.assertIn("email", data)
        self.assertIn("type", data)

    def test_delete_admin(self):
        # Assuming there is an admin with id 2
        res = self.client.delete('/admin/2', headers={})
        self.assertEqual(res.status_code, 200)
        data = json.loads(res.data)
        self.assertEqual(data["status"], "success")

    def test_delete_root_admin(self):
        # Trying to delete root admin
        res = self.client.delete('/admin/0', headers={})
        self.assertEqual(res.status_code, 200)
        data = json.loads(res.data)
        self.assertEqual(data["status"], "failure")
        self.assertEqual(data["message"], "不能删除root用户")

class TestAdminPassword(AdminCase):
    def test_normal(self):
        # Assuming there is an admin with id 2 and password 'oldpassword'
        res = post_json(self.client, '/admin/1/update-password', {
                'old_password': self.default_admin_attrs['password'],
                'new_password': 'NewPassword123!'
            }, headers={})
        self.assertEqual(res.status_code, 200)
        data = json.loads(res.data)
        self.assertEqual(data["status"], "success")

    def test_non_existent_admin(self):
        # Trying to update password for a non-existent admin
        res = post_json(self.client, '/admin/100/update-password', {
                'old_password': 'oldpassword',
                'new_password': 'NewPassword123!'
            }, headers={})
        self.assertEqual(res.status_code, 200)
        data = json.loads(res.data)
        self.assertEqual(data["status"], "failure")
        self.assertEqual(data["message"], "账户不存在")

    def test_wrong_old_password(self):
        # Assuming there is an admin with id 2 and password 'oldpassword'
        res = post_json(self.client, '/admin/2/update-password', {
                'old_password': 'wrongpassword',
                'new_password': 'NewPassword123!'
            }, headers={})
        self.assertEqual(res.status_code, 200)
        data = json.loads(res.data)
        self.assertEqual(data["status"], "failure")
        self.assertEqual(data["message"], "密码错误")

    def test_weak_new_password(self):
        # Assuming there is an admin with id 2 and password 'oldpassword'
        res = post_json(self.client, '/admin/1/update-password', {
                'old_password': self.default_admin_attrs['password'],
                'new_password': 'weak'
            }, headers={})
        self.assertEqual(res.status_code, 200)
        data = json.loads(res.data)
        self.assertEqual(data["status"], "failure")
        self.assertEqual(data["message"], "密码不合规范")

    # '/admin/forget-password'
    @mock.patch('grimm.utils.emailverify.send')
    def test_reset(self, mocked_func):
        mocked_func.return_value = 0

        res = self.client.get('/admin/forget-password?email={}'.format(self.default_admin_attrs['email']))
        self.assertEqual(res.status_code, 200)
        data = json.loads(res.data)
        self.assertEqual(data["status"], "success")

        # Check the password in the database is updated and encrypted
        with self.app.app_context():
            admin_info = db.session.query(Admin).filter(Admin.email == self.default_admin_attrs['email']).first()
            self.assertIsNotNone(admin_info)
            self.assertTrue(bcrypt.checkpw(admin_info.password,
                bcrypt.hashpw(admin_info.password, bcrypt.gensalt(constants.DEFAULT_PASSWORD_SALT))))
            self.assertFalse(bcrypt.checkpw(self.default_admin_attrs['password'],
                bcrypt.hashpw(admin_info.password, bcrypt.gensalt(constants.DEFAULT_PASSWORD_SALT))))

    def test_reset_non_existent_admin(self):
        # Trying to reset password for a non-existent admin
        res = self.client.get('/admin/forget-password?email=nonexistent@test.com')
        self.assertEqual(res.status_code, 200)
        data = json.loads(res.data)
        self.assertEqual(data["status"], "failure")
        self.assertEqual(data["message"], "未注册邮箱")

if __name__ == "__main__":
    unittest.main()
