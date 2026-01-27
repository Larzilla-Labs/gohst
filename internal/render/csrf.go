package render

import (
	"fmt"
	"html/template"
	"net/http"

	"gohst/internal/config"
	"gohst/internal/session"
)

type CSRF struct {
	Token string
	Input template.HTML
}

const CSRFInputTemplate = `<input type="hidden" name="%s" value="%s">`

func GetCSRF(r *http.Request) *CSRF {
	sess := session.FromContext(r.Context())
	if sess == nil {
		return &CSRF{Token: "", Input: template.HTML("")}
	}
	rawToken, _ := sess.GetCSRF()
	tokenName := config.APP_CSRF_KEY
	token := rawToken.(string)

	return &CSRF{
		Token: token,
		Input: template.HTML(fmt.Sprintf(CSRFInputTemplate, tokenName, token)),
	}
}
