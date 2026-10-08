// Copyright 2026 Cisco Systems, Inc.
// SPDX-License-Identifier: Apache-2.0
import DefaultTheme from "vitepress/theme";
import "./custom.css";
import AppScreenshot from "./components/AppScreenshot.vue";
import HomePage from "./components/HomePage.vue";

export default {
  extends: DefaultTheme,
  enhanceApp({ app }) {
    app.component("AppScreenshot", AppScreenshot);
    app.component("HomePage", HomePage);
  },
};
