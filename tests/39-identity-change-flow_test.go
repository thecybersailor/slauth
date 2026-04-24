package tests

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/suite"
	"github.com/thecybersailor/slauth/pkg/consts"
	identitychange "github.com/thecybersailor/slauth/pkg/flow/identity_change"
	"github.com/thecybersailor/slauth/pkg/services"
	"github.com/thecybersailor/slauth/pkg/types"
)

type IdentityChangeFlowTestSuite struct {
	TestSuite
	helper *TestHelper
}

func (suite *IdentityChangeFlowTestSuite) SetupSuite() {
	suite.TestSuite.SetupSuite()
	suite.helper = NewTestHelper(suite.DB, suite.Router, suite.TestInstance, suite.EmailProvider, suite.SMSProvider)
}

func (suite *IdentityChangeFlowTestSuite) signUpAndConfirm(email, password string) *services.User {
	signupResponse := suite.helper.MakePOSTRequest(suite.T(), "/auth/signup", S{
		"email":    email,
		"password": password,
	})
	suite.Equal(200, signupResponse.ResponseRecorder.Code)
	suite.Nil(signupResponse.Error)

	lastEmail := suite.helper.GetMockEmailProvider().GetLastEmail()
	suite.Require().NotNil(lastEmail)

	body := lastEmail.Body
	tokenStart := len("token=")
	token := ""
	for i := 0; i < len(body)-tokenStart; i++ {
		if body[i:i+tokenStart] == "token=" {
			start := i + tokenStart
			end := start
			for end < len(body) && body[end] != ' ' && body[end] != '"' && body[end] != '\'' && body[end] != '>' && body[end] != '&' {
				end++
			}
			token = body[start:end]
			break
		}
	}
	suite.Require().NotEmpty(token)

	confirmResponse := suite.helper.MakeGETRequest(suite.T(), "/auth/confirm?token="+token)
	suite.Equal(200, confirmResponse.ResponseRecorder.Code)
	suite.Nil(confirmResponse.Error)

	user, err := suite.AuthService.GetUserService().GetByEmail(suite.T().Context(), email)
	suite.Require().NoError(err)
	return user
}

func (suite *IdentityChangeFlowTestSuite) TestIdentityChangeFlowRejectsInsufficientAAL() {
	email := fmt.Sprintf("identity-flow-aal-%d@example.com", time.Now().UnixNano())
	user := suite.signUpAndConfirm(email, "IdentityFlow123!")

	_, err := identitychange.Start(
		suite.T().Context(),
		suite.AuthService,
		user,
		identitychange.KindEmail,
		fmt.Sprintf("next-%d@example.com", time.Now().UnixNano()),
		types.AALLevel1,
	)
	suite.ErrorIs(err, consts.INSUFFICIENT_AAL)
}

func (suite *IdentityChangeFlowTestSuite) TestIdentityChangeFlowRejectsSameValueAndConflict() {
	email := fmt.Sprintf("identity-flow-same-%d@example.com", time.Now().UnixNano())
	user := suite.signUpAndConfirm(email, "IdentityFlow123!")

	_, err := identitychange.Start(
		suite.T().Context(),
		suite.AuthService,
		user,
		identitychange.KindEmail,
		email,
		types.AALLevel2,
	)
	suite.Error(err)

	conflictEmail := fmt.Sprintf("identity-flow-conflict-%d@example.com", time.Now().UnixNano())
	suite.signUpAndConfirm(conflictEmail, "IdentityFlow123!")

	_, err = identitychange.Start(
		suite.T().Context(),
		suite.AuthService,
		user,
		identitychange.KindEmail,
		conflictEmail,
		types.AALLevel2,
	)
	suite.Error(err)
}

func (suite *IdentityChangeFlowTestSuite) TestIdentityChangeFlowPersistsPendingStateWithoutMutatingUser() {
	email := fmt.Sprintf("identity-flow-pending-%d@example.com", time.Now().UnixNano())
	user := suite.signUpAndConfirm(email, "IdentityFlow123!")
	newEmail := fmt.Sprintf("identity-flow-next-%d@example.com", time.Now().UnixNano())

	result, err := identitychange.Start(
		suite.T().Context(),
		suite.AuthService,
		user,
		identitychange.KindEmail,
		newEmail,
		types.AALLevel2,
	)
	suite.Require().NoError(err)
	suite.NotZero(result.FlowStateID)
	suite.NotEmpty(result.SessionCode)

	flowState, err := suite.AuthService.GetFlowStateByID(suite.T().Context(), result.FlowStateID)
	suite.Require().NoError(err)
	state, err := identitychange.DecodeFlowState(flowState)
	suite.Require().NoError(err)
	suite.Equal(identitychange.KindEmail, state.Kind)
	suite.Equal(identitychange.StageVerifyNew, state.Stage)
	suite.Equal(email, state.CurrentValue)
	suite.Equal(newEmail, state.NewValue)

	reloaded, err := suite.AuthService.GetUserService().GetByHashID(suite.T().Context(), user.HashID)
	suite.Require().NoError(err)
	suite.Equal(email, reloaded.GetEmail())
}

func TestIdentityChangeFlowTestSuite(t *testing.T) {
	suite.Run(t, new(IdentityChangeFlowTestSuite))
}
