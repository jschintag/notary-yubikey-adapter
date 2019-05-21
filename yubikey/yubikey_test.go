package yubikey

import (
	"crypto/rand"
	"testing"

	"github.com/miekg/pkcs11"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	"github.com/theupdateframework/notary/trustmanager/pkcs11/common"
	"github.com/theupdateframework/notary/tuf/data"
	"github.com/theupdateframework/notary/tuf/utils"
)

const (
	userpin = "123456"
	sopin   = "010203040506070801020304050607080102030405060708"
)

func init() {
	logrus.SetLevel(logrus.DebugLevel)
}

func getKeyStoreAndSession(t *testing.T) (*KeyStore, pkcs11.SessionHandle) {
	ks := NewKeyStore()
	session, err := ks.SetupHSMEnv()
	require.NoError(t, err)
	return ks, session
}

func TestLogin(t *testing.T) {
	ks, session := getKeyStoreAndSession(t)
	defer ks.CloseSession(session)
	err := pkcs11Ctx.Login(session, pkcs11.CKU_USER, userpin)
	require.NoError(t, err)
	pkcs11Ctx.Logout(session)
}

func TestAddAndRetrieveKey(t *testing.T) {
	defer Cleanup()
	//clearAllKeys(t)
	ks, session := getKeyStoreAndSession(t)
	defer ks.CloseSession(session)
	privKey, err := utils.GenerateECDSAKey(rand.Reader)
	require.NoError(t, err)
	slotID, err := ks.GetNextEmptySlot(session)
	require.NoError(t, err)
	slot := common.HardwareSlot{
		Role:   data.CanonicalRootRole,
		SlotID: slotID,
		KeyID:  privKey.ID(),
	}
	err = ks.AddECDSAKey(session, privKey, slot, sopin, data.CanonicalRootRole)
	require.NoError(t, err)
	pubKey, role, err := ks.GetECDSAKey(session, slot, userpin)
	require.NoError(t, err)
	require.Equal(t, role, data.CanonicalRootRole)
	require.Equal(t, privKey.Public(), pubKey.Public())
}
