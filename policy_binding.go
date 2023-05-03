package iamsql

type PolicyBinding struct {
	ID           int    `gorm:"column:iam_policy_bindings_id"`
	Resource     string `gorm:"column:resource"`
	BindingIndex int64  `gorm:"column:binding_index"`
	Role         string `gorm:"column:role"`
	MemberIndex  int64  `gorm:"column:member_index"`
	Member       string `gorm:"column:member"`
}
