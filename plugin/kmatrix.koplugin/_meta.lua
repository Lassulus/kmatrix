local _ = require("gettext")

-- No `name` key: KOReader derives it from the directory and warns that a
-- `name` in _meta.lua is deprecated and ignored (pluginloader.lua:256-259).
return {
    fullname = _("Matrix"),
    description = _("Matrix chat client."),
}
