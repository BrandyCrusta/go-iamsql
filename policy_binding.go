package iamsql

type PolicyBinding struct {
	Resource     string `gorm:"column:resource"`
	BindingIndex int64  `gorm:"column:binding_index"`
	Role         string `gorm:"column:role"`
	MemberIndex  int64  `gorm:"column:member_index"`
	Member       string `gorm:"column:member"`
}
