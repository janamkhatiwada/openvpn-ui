package models

import (
	"errors"
	"time"

	"github.com/beego/beego/v2/client/orm"
	"github.com/beego/beego/v2/core/validation"
)

type User struct {
	Id            int64
	Login         string    `orm:"size(64);unique" form:"Login" valid:"Required;"`
	IsAdmin       bool      `orm:"default(false)" form:"IsAdmin" valid:"Required;"`
	Name          string    `orm:"size(64);unique" form:"Name" valid:"Required;"`
	Email         string    `orm:"size(64);unique" form:"Email" valid:"Required;Email"`
	Password      string    `orm:"size(32)" form:"Password" valid:"Required;MinSize(6)"`
	Repassword    string    `orm:"-" form:"Repassword" valid:"Required"`
	PIN           string    `orm:"size(30)" form:"PIN" valid:"Required;MinSize(4);MaxSize(30)"` // Added PIN field
	Lastlogintime time.Time `orm:"type(datetime);null" form:"-"`
	Created       time.Time `orm:"auto_now_add;type(datetime)"`
	Updated       time.Time `orm:"auto_now;type(datetime)"`
	Allowed       bool      `orm:"default(false)" form:"Allowed" valid:"Required;"`
	HasCert       bool      `orm:"-"` // Transient field, not stored in the database

}

// Check if the user has a certificate
func (u *User) CheckHasCert() (bool, error) {
	o := orm.NewOrm()
	count, err := o.QueryTable("certificate").Filter("UserId", u.Id).Count()
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

func (u *User) Valid(v *validation.Validation) {
	if u.Password != u.Repassword {
		_ = v.SetError("Repassword", "Passwords do not match")
	}
}

func (u *User) Insert() error {
	if _, err := orm.NewOrm().Insert(u); err != nil {
		return err
	}
	return nil
}

// Read wrapper
func (u *User) Read(fields ...string) error {
	if err := orm.NewOrm().Read(u, fields...); err != nil {
		return err
	}
	return nil
}

// Update wrapper
func (u *User) Update(fields ...string) error {
	if _, err := orm.NewOrm().Update(u, fields...); err != nil {
		return err
	}
	return nil
}

// Delete wrapper
func (u *User) Delete() error {
	if _, err := orm.NewOrm().Delete(u); err != nil {
		return err
	}
	return nil
}

// GetUserByEmail retrieves a user by their email address
func GetUserByEmail(email string) (*User, error) {
	user := &User{Email: email}
	err := user.Read("Email")
	if err != nil {
		if err == orm.ErrNoRows {
			return nil, errors.New("user not found")
		}
		return nil, err
	}
	return user, nil
}
