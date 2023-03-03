package security

import (
	"github.com/gin-gonic/gin"
	"github.com/spf13/viper"
	"io"
	"net/http"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"strconv"
	"treehollow-v3-backend/pkg/base"
	"treehollow-v3-backend/pkg/consts"
	"treehollow-v3-backend/pkg/logger"
	"treehollow-v3-backend/pkg/utils"
)

// 由于 oauth 的特殊性，邮箱必须在过程中拿到，但我暂时没搞明白怎么把一个值放到PostForm里，所以先把所有中间件都搞一起来
func oauthTotalCheckMiddleware(c *gin.Context) {
	pwHashed := c.PostForm("password_hashed")
	code := strings.ToLower(c.PostForm("code"))
	deviceTypeStr := c.PostForm("device_type")
	deviceInfo := c.PostForm("device_info")
	iosDeviceToken := c.PostForm("ios_device_token")

	if len(code) > 20 || len(pwHashed) > 64 || len(deviceInfo) > 100 || len(iosDeviceToken) > 100 {
		base.HttpReturnWithCodeMinusOneAndAbort(c, logger.NewSimpleError("LoginParamsOutOfBound", "参数错误", logger.WARN))
		return
	}
	deviceTypeInt, err := strconv.Atoi(deviceTypeStr)
	deviceType := base.DeviceType(deviceTypeInt)
	if err != nil || (deviceType != base.AndroidDevice &&
		deviceType != base.IOSDevice &&
		deviceType != base.WebDevice) {
		base.HttpReturnWithCodeMinusOneAndAbort(c, logger.NewSimpleError("DeviceTypeError", "参数device_type错误", logger.WARN))
		return
	}

	client := http.Client{}

	client_id := viper.GetString("oauth_client_id")
	client_secret := viper.GetString("oauth_client_secret")
	oauthUrl := fmt.Sprintf("https://github.com/login/oauth/access_token?client_id=%s&client_secret=%s&code=%s",
		client_id, client_secret, code)

	req, _ := http.NewRequest("GET", oauthUrl, nil)
	resp, err := client.Do(req)
	if (err != nil) {
		base.HttpReturnWithCodeMinusOneAndAbort(c, logger.NewSimpleError("NetworkError", "连接OAuth失败", logger.WARN))
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	res := strings.Split(strings.Split(string(body), "&")[0], "=")

	if res[0] != "access_token" {
		base.HttpReturnWithCodeMinusOneAndAbort(c, logger.NewSimpleError("OAuthError", "OAuth Code无效", logger.WARN))
		return
	}

	token := res[1]
	tokenUrl := "https://api.github.com/user"
	req, _ = http.NewRequest("GET", tokenUrl, nil)
	req.Header.Add("accept", "application/json")
	req.Header.Add("Authorization", fmt.Sprintf("token %s", token))
	resp, err = client.Do(req)
	if (err != nil) {
		base.HttpReturnWithCodeMinusOneAndAbort(c, logger.NewSimpleError("NetworkError", "连接OAuth失败", logger.WARN))
		return
	}
	defer resp.Body.Close()
	body, _ = io.ReadAll(resp.Body)
	var ret map[string]interface{}
	_ = json.Unmarshal(body, &ret)
	email_ret := ret["email"]
	if email_ret == nil {
		base.HttpReturnWithCodeMinusOneAndAbort(c, logger.NewSimpleError("OAuthError", "无法获取邮箱地址，请检查账户设置", logger.WARN))
		return
	}

	email := strings.ToLower(email_ret.(string))
	emailCheck, err := regexp.Compile(viper.GetString("email_check_regex"))
	if err != nil {
		base.HttpReturnWithCodeMinusOneAndAbort(c, logger.NewError(err, "RegexError", "服务器配置错误，请联系管理员。"))
		return
	}
	if !emailCheck.MatchString(email) {
		emailWhitelist := viper.GetStringSlice("email_whitelist")
		if _, ok := utils.ContainsString(emailWhitelist, email); !ok {
			base.HttpReturnWithCodeMinusOneAndAbort(c, logger.NewSimpleError("EmailRegexCheckNotPass", "很抱歉，您的邮箱无法注册"+viper.GetString("name"), logger.INFO))
			return
		}
	}

	emailHash := utils.HashEmail(email)

	var count int64
	err = base.GetDb(false).Where("email_hash = ?", emailHash).
		Model(&base.Email{}).Count(&count).Error
	if err != nil {
		base.HttpReturnWithCodeMinusOneAndAbort(c, logger.NewError(err, "CheckAccountRegisteredFailed", consts.DatabaseReadFailedString))
		return
	}
	if count == 1 {
		base.HttpReturnWithCodeMinusOneAndAbort(c, logger.NewSimpleError("AlreadyRegisteredError", "你已经注册过了！", logger.WARN))
		return
	}

	c.Set("email", email)
	c.Set("email_hash", emailHash)
	c.Set("device_type", deviceType)
	c.Next()
}
