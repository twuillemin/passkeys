package handler

import (
	"github.com/labstack/echo/v4"
	hankoJwk "github.com/teamhanko/passkey-server/crypto/jwk"
	"github.com/teamhanko/passkey-server/persistence/models"
	"net/http"
)

type WellKnownHandler struct{}

//	[{
//	 "relation": ["delegate_permission/common.handle_all_urls"],
//	 "target": {
//	   "namespace": "android_app",
//	   "package_name": "com.example",
//	   "sha256_cert_fingerprints":
//	   ["14:6D:E9:83:C5:73:06:50:D8:EE:B9:95:2F:34:FC:64:16:A0:83:42:E6:1D:BE:A8:8A:04:96:B2:3F:CF:44:E5"]
//	 }
//	}]

type AssetLinkTarget struct {
	Namespace    string   `json:"namespace"`
	PackageName  string   `json:"package_name,omitempty"`
	Site         string   `json:"site,omitempty"`
	FingerPrints []string `json:"sha256_cert_fingerprints,omitempty"`
}
type AssetLink struct {
	Relation []string        `json:"relation"`
	Target   AssetLinkTarget `json:"target"`
}

func NewWellKnownHandler() *WellKnownHandler {
	return &WellKnownHandler{}
}

func (h *WellKnownHandler) GetPublicKeys(ctx echo.Context) error {
	tenant := ctx.Get("tenant").(*models.Tenant)
	if tenant == nil {
		return echo.NewHTTPError(http.StatusNotFound, "unable to find tenant")
	}

	manager := ctx.Get("jwk_manager").(hankoJwk.Manager)
	keys, err := manager.GetPublicKeys(tenant.ID)
	if err != nil {
		ctx.Logger().Error(err)
		return echo.NewHTTPError(http.StatusInternalServerError, "unable to get JWKs")
	}

	ctx.Response().Header().Add("Cache-Control", "max-age=600")
	return ctx.JSON(http.StatusOK, keys)
}

func (h *WellKnownHandler) GetAssetLinks(ctx echo.Context) error {
	assetLinks := []AssetLink{
		{
			Relation: []string{
				"delegate_permission/common.handle_all_urls",
			},
			Target: AssetLinkTarget{
				Namespace:   "android_app",
				PackageName: "com.example.testpasskey2",
				FingerPrints: []string{
					"F0:19:A4:58:07:FE:67:A8:0B:C4:B1:7C:48:D6:B7:58:DC:77:F0:D6:A4:B2:FF:58:7D:EF:EA:D8:E2:21:69:DC",
				},
			},
		},
		{
			Relation: []string{
				"delegate_permission/common.get_login_creds",
			},
			Target: AssetLinkTarget{
				Namespace:   "android_app",
				PackageName: "com.example.testpasskey2",
				FingerPrints: []string{
					"F0:19:A4:58:07:FE:67:A8:0B:C4:B1:7C:48:D6:B7:58:DC:77:F0:D6:A4:B2:FF:58:7D:EF:EA:D8:E2:21:69:DC",
				},
			},
		},
		{
			Relation: []string{
				"delegate_permission/common.get_login_creds",
			},
			Target: AssetLinkTarget{
				Namespace: "web",
				Site:      "https://devmobile.ctminsights.com",
			},
		},
	}

	ctx.Response().Header().Add("Cache-Control", "max-age=600")
	return ctx.JSON(http.StatusOK, assetLinks)
}
