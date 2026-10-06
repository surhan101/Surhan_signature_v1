/*
 * Surhan Signature - Phase 26E Hardened
 * Universal In-Page Desk form integration for any DocType containing ac_footer.
 */

(function () {
  if (window.__surhan_internal_signature_loaded) return;
  window.__surhan_internal_signature_loaded = true;

  // Setup auto-fetch for AC Footer Signer child table
  if (frappe.model && frappe.model.add_fetch) {
    frappe.model.add_fetch("employee", "employee_name", "full_name");
    frappe.model.add_fetch("employee", "user_id", "user");
    frappe.model.add_fetch("employee", "designation", "designation");
    frappe.model.add_fetch("employee", "department", "department");
  }

  // Handle instant employee selection in AC Footer Signer child table
  frappe.ui.form.on("AC Footer Signer", {
    employee: function (frm, cdt, cdn) {
      const row = locals[cdt] && locals[cdt][cdn];
      if (!row || !row.employee) return;

      frappe.db.get_value(
        "Employee",
        row.employee,
        ["employee_name", "user_id", "designation", "department"],
        function (r) {
          if (!r) return;
          frappe.model.set_value(cdt, cdn, "full_name", r.employee_name || "");
          frappe.model.set_value(cdt, cdn, "user", r.user_id || "");
          frappe.model.set_value(cdt, cdn, "designation", r.designation || "");
          frappe.model.set_value(cdt, cdn, "department", r.department || "");
          if (!row.action_required) {
            frappe.model.set_value(cdt, cdn, "action_required", "Saved Signature");
          }
          if (!row.sign_order) {
            frappe.model.set_value(cdt, cdn, "sign_order", 1);
          }
        }
      );
    }
  });

  function has_ac_footer_field(frm) {
    if (!frm || !frm.doc) return false;
    if (frm.fields_dict && frm.fields_dict.ac_footer) return true;
    if (frm.doc.ac_footer !== undefined) return true;
    if (frm.meta && frm.meta.fields) {
      return (frm.meta.fields || []).some(function (df) {
        return df && (
          df.fieldname === "ac_footer" ||
          String(df.label || "").toLowerCase().trim() === "ac footer"
        );
      });
    }
    return false;
  }

  function call_silent(method, args) {
    return frappe.call({
      method: method,
      args: args || {},
      freeze: false
    });
  }

  function call_with_freeze(method, args, freeze_message) {
    return frappe.call({
      method: method,
      args: args || {},
      freeze: true,
      freeze_message: freeze_message || __("Processing...")
    });
  }

  function refresh_signature_indicator(frm, ctx) {
    if (!frm.dashboard) return;

    const state = ctx.state || {};
    const counts = state.status_counts || {};

    if (ctx.complete) {
      frm.dashboard.add_indicator(__("مكتمل التوقيع والاعتماد"), "green");
    } else if (ctx.can_sign) {
      frm.dashboard.add_indicator(__("بانتظار توقيعك / اعتمادك"), "orange");
    } else if ((state.count || 0) > 0) {
      frm.dashboard.add_indicator(
        __("التوقيع الداخلي: {0} توقيع معلق", [state.count]),
        counts.Rejected ? "red" : "blue"
      );
    }
  }

  function open_inpage_signature_dialog(frm, ctx) {
    const profile = ctx.profile || {};
    const has_saved_signature = Boolean(profile.signature_png);
    const signable = ctx.my_pending_requests || [];
    const first_req = ctx.first_pending || (signable.length ? signable[0] : null);
    const my_req = signable.find(r => r.requested_user === frappe.session.user) || first_req;
    const target_request_name = my_req ? my_req.name : null;

    // Check capabilities
    const caps = (ctx.capabilities && ctx.capabilities.effective_capabilities) || {};
    const can_use_saved = caps.can_use_saved_signature !== false;
    const can_draw = (caps.can_draw_direction !== false || caps.can_write_direction_text !== false);
    const can_reject = caps.can_reject !== false;

    // Active tab logic
    const active_tab = (can_use_saved && has_saved_signature) ? "saved" : (can_draw ? "direction" : "saved");

    const html_content = `
      <div style="direction: rtl; text-align: right; font-family: inherit;">
        <!-- Tab Headers -->
        <div style="display: flex; gap: 8px; border-bottom: 2px solid #e5e7eb; margin-bottom: 16px;">
          ${can_use_saved ? `
            <button type="button" class="btn btn-sm surhan-tab-btn" data-tab="saved" style="font-weight: 700; ${active_tab === 'saved' ? 'border-bottom: 2px solid #2563eb; color: #2563eb;' : 'color: #6b7280; border: none;'} background: none; border-radius: 0; padding: 8px 16px;">
              ✍️ التوقيع المحفوظ
            </button>
          ` : ''}
          ${can_draw ? `
            <button type="button" class="btn btn-sm surhan-tab-btn" data-tab="direction" style="font-weight: 700; ${active_tab === 'direction' ? 'border-bottom: 2px solid #2563eb; color: #2563eb;' : 'color: #6b7280; border: none;'} background: none; border-radius: 0; padding: 8px 16px;">
              🖋️ رسم توقيع مباشر / توجيه
            </button>
          ` : ''}
          ${can_reject ? `
            <button type="button" class="btn btn-sm surhan-tab-btn" data-tab="reject" style="font-weight: 700; color: #dc2626; background: none; border: none; border-radius: 0; padding: 8px 16px;">
              ❌ رفض / إرجاع
            </button>
          ` : ''}
        </div>

        <!-- Tab 1: Saved Signature -->
        <div id="surhan_tab_saved" class="surhan-tab-pane" style="display: ${active_tab === 'saved' ? 'block' : 'none'};">
          ${has_saved_signature ? `
            <div style="background: #f9fafb; border: 1px solid #e5e7eb; border-radius: 12px; padding: 16px; text-align: center; margin-bottom: 16px;">
              <p style="color: #4b5563; font-size: 13px; margin-bottom: 10px;">معاينة التوقيع المعتمد الخاص بك:</p>
              <img src="${profile.signature_png}" style="max-height: 120px; max-width: 100%; border: 1px dashed #d1d5db; background: #fff; border-radius: 8px; padding: 6px;" />
              <div style="margin-top: 8px; font-weight: 600; color: #111827;">${frappe.utils.escape_html(profile.full_name || frappe.session.user_fullname || frappe.session.user)}</div>
            </div>
            <button type="button" id="btn_apply_saved_sig" class="btn btn-primary btn-block" style="background: #10b981; border-color: #10b981; font-weight: 600; border-radius: 8px; padding: 10px;">
              ✔️ اعتماد بالتوقيع المحفوظ الفوري
            </button>
          ` : `
            <div style="background: #fffbeb; border: 1px solid #fde68a; border-radius: 12px; padding: 16px; text-align: center; margin-bottom: 16px;">
              <p style="color: #92400e; font-size: 14px; margin-bottom: 6px; font-weight: 600;">لا يوجد توقيع محفوظ مسجل لحسابك</p>
              <p style="color: #b45309; font-size: 12px; margin: 0;">يمكنك استخدام تبويب "رسم توقيع مباشر / توجيه" لرسم توقيعك مباشرة على الشاشة.</p>
            </div>
          `}
        </div>

        <!-- Tab 2: Direction & Live Drawing -->
        <div id="surhan_tab_direction" class="surhan-tab-pane" style="display: ${active_tab === 'direction' ? 'block' : 'none'};">
          <div style="margin-bottom: 12px;">
            <label style="font-weight: 600; font-size: 12px; display: block; margin-bottom: 4px;">نص التوجيه أو الملاحظات (اختياري):</label>
            <textarea id="surhan_dir_text" class="form-control" rows="2" placeholder="اكتب التوجيه أو الملاحظات هنا..." style="border-radius: 8px; resize: vertical;"></textarea>
          </div>

          <div style="margin-bottom: 8px; display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 8px;">
            <label style="font-weight: 700; font-size: 13px; margin: 0; color: #1e293b;">🖋️ مساحة الرسم والتوقيع فائقة الدقة (Ultra-HD):</label>
            <div style="display: flex; gap: 6px; align-items: center;">
              <span style="font-size: 11px; color: #64748b; font-weight: 600;">الحبر:</span>
              <button type="button" class="btn btn-xs surhan-color-btn active" data-color="#0f172a" style="width: 20px; height: 20px; border-radius: 50%; background: #0f172a; border: 2px solid #3b82f6; padding: 0; cursor: pointer;" title="أسود داكن"></button>
              <button type="button" class="btn btn-xs surhan-color-btn" data-color="#1e40af" style="width: 20px; height: 20px; border-radius: 50%; background: #1e40af; border: 2px solid transparent; padding: 0; cursor: pointer;" title="أزرق ملكي"></button>
              <button type="button" class="btn btn-xs surhan-color-btn" data-color="#047857" style="width: 20px; height: 20px; border-radius: 50%; background: #047857; border: 2px solid transparent; padding: 0; cursor: pointer;" title="أخضر رسمي"></button>
              <span style="border-left: 1px solid #cbd5e1; height: 16px; margin: 0 4px;"></span>
              <button type="button" id="btn_canvas_undo" class="btn btn-xs btn-default" style="border-radius: 6px; font-weight: 600;">↩️ تراجع</button>
              <button type="button" id="btn_canvas_clear" class="btn btn-xs btn-default" style="border-radius: 6px; font-weight: 600; color: #ef4444;">🗑️ مسح</button>
              <span style="font-size: 11px; color: #64748b; font-weight: 600;">السماكة:</span>
              <input type="range" id="surhan_canvas_pen" min="1.5" max="6" step="0.5" value="2.5" style="width: 65px; cursor: pointer;">
            </div>
          </div>

          <div style="position: relative; border: 2px solid #cbd5e1; border-radius: 12px; overflow: hidden; background: #ffffff; touch-action: none; margin-bottom: 12px; box-shadow: inset 0 2px 6px rgba(0,0,0,0.03);">
            <canvas id="surhan_live_canvas" style="width: 100%; height: 320px; display: block; cursor: crosshair;"></canvas>
            <div style="position: absolute; bottom: 35px; left: 30px; right: 30px; border-bottom: 1.5px dashed #cbd5e1; pointer-events: none; text-align: left;">
              <span style="font-size: 10px; color: #94a3b8; background: #fff; padding: 0 6px;">✕ خط التوقيع / Signature Baseline</span>
            </div>
          </div>

          ${has_saved_signature ? `
            <div style="margin-bottom: 14px; background: #f0fdf4; border: 1px solid #bbf7d0; padding: 10px 14px; border-radius: 8px; display: flex; align-items: center; gap: 10px;">
              <span style="font-size: 18px;">🛡️</span>
              <div style="flex: 1;">
                <div style="font-size: 12.5px; font-weight: 700; color: #166534;">
                  سيتم استدعاء توقيعك الثابت المعتمد تلقائياً مع هذا التوجيه
                </div>
                <div style="font-size: 11px; color: #15803d; margin-top: 2px;">
                  التوقيع المحفوظ محمي بالكامل في النظام ولا يتغير إلا من لوحة تحكم الإدارة.
                </div>
              </div>
              <input type="hidden" id="surhan_attach_saved" value="1">
            </div>
          ` : ""}

          <button type="button" id="btn_apply_direction_sig" class="btn btn-primary btn-block" style="font-weight: 600; border-radius: 8px; padding: 10px;">
            💾 تثبيت التوجيه والاعتماد
          </button>
        </div>

        <!-- Tab 3: Reject -->
        <div id="surhan_tab_reject" class="surhan-tab-pane" style="display: none;">
          <div style="margin-bottom: 14px;">
            <label style="font-weight: 600; font-size: 13px; display: block; margin-bottom: 4px; color: #dc2626;">سبب الرفض أو الإرجاع:</label>
            <textarea id="surhan_reject_reason" class="form-control" rows="3" placeholder="اكتب سبب الرفض أو الإرجاع..." style="border-radius: 8px;"></textarea>
          </div>
          <button type="button" id="btn_apply_reject_sig" class="btn btn-danger btn-block" style="font-weight: 600; border-radius: 8px; padding: 10px;">
            ❌ تأكيد الرفض / الإرجاع
          </button>
        </div>
      </div>
    `;

    const d = new frappe.ui.Dialog({
      title: __("اعتماد وتوقيع المستند"),
      size: "large",
      fields: [
        {
          fieldtype: "HTML",
          fieldname: "sig_html",
          options: html_content
        }
      ],
      primary_action_label: __("إغلاق"),
      primary_action: function () {
        d.hide();
      }
    });

    d.show();

    // Tab switching logic
    setTimeout(function () {
      const $wrapper = d.$wrapper;

      $wrapper.find(".surhan-tab-btn").on("click", function () {
        const tab = $(this).data("tab");
        $wrapper.find(".surhan-tab-btn").css({
          "color": "#6b7280",
          "border-bottom": "none"
        });
        $(this).css({
          "color": tab === "reject" ? "#dc2626" : "#2563eb",
          "border-bottom": tab === "reject" ? "2px solid #dc2626" : "2px solid #2563eb"
        });
        $wrapper.find(".surhan-tab-pane").hide();
        $wrapper.find("#surhan_tab_" + tab).show();

        if (tab === "direction" && canvas_setup) {
          canvas_setup.resize();
        }
      });

      function get_selected_request_name() {
        return target_request_name || (first_req ? first_req.name : null);
      }

      // Action: Apply Saved Signature
      $wrapper.find("#btn_apply_saved_sig").on("click", function () {
        const req_name = get_selected_request_name();
        call_with_freeze(
          "surhan_signature.api.apply_document_signature_unified",
          {
            reference_doctype: frm.doc.doctype,
            reference_name: frm.doc.name,
            request_name: req_name,
            signature_type: "saved"
          },
          __("جاري تطبيق التوقيع المحفوظ...")
        ).then(function () {
          frappe.show_alert({ message: __("تم التوقيع والاعتماد بنجاح"), indicator: "green" });
          d.hide();
          frm.reload_doc();
        });
      });

      // Canvas setup for live drawing
      let canvas_setup = null;
      const canvas_el = $wrapper.find("#surhan_live_canvas")[0];
      if (canvas_el) {
        canvas_setup = init_signature_canvas(canvas_el, $wrapper);
        if (active_tab === "direction") {
          setTimeout(function () { canvas_setup.resize(); }, 60);
        }
      }

      // Action: Apply Direction / Live Drawing
      $wrapper.find("#btn_apply_direction_sig").on("click", function () {
        const req_name = get_selected_request_name();
        const text = ($wrapper.find("#surhan_dir_text").val() || "").trim();
        const $attachEl = $wrapper.find("#surhan_attach_saved");
        const attach_saved = $attachEl.length ? ($attachEl.is(":checkbox") ? ($attachEl.is(":checked") ? 1 : 0) : 1) : 1;

        if (!text && !svg) {
          frappe.msgprint(__("يرجى كتابة نص التوجيه أو رسم التوقيع أولاً."));
          return;
        }

        call_with_freeze(
          "surhan_signature.api.apply_document_signature_unified",
          {
            reference_doctype: frm.doc.doctype,
            reference_name: frm.doc.name,
            request_name: req_name,
            signature_type: "direction",
            direction_text: text,
            direction_svg: svg,
            attach_saved_signature: attach_saved
          },
          __("جاري حفظ التوجيه والاعتماد...")
        ).then(function () {
          frappe.show_alert({ message: __("تم تثبيت التوجيه والاعتماد بنجاح"), indicator: "green" });
          d.hide();
          frm.reload_doc();
        });
      });

      // Action: Reject
      $wrapper.find("#btn_apply_reject_sig").on("click", function () {
        const req_name = get_selected_request_name();
        const reason = ($wrapper.find("#surhan_reject_reason").val() || "").trim();

        if (!reason) {
          frappe.msgprint(__("يرجى كتابة سبب الرفض أو الإرجاع."));
          return;
        }

        call_with_freeze(
          "surhan_signature.api.apply_document_signature_unified",
          {
            reference_doctype: frm.doc.doctype,
            reference_name: frm.doc.name,
            request_name: req_name,
            signature_type: "reject",
            reason: reason
          },
          __("جاري إرجاع الطلب...")
        ).then(function () {
          frappe.show_alert({ message: __("تم رفض / إرجاع الطلب بنجاح"), indicator: "red" });
          d.hide();
          frm.reload_doc();
        });
      });
    }, 200);
  }

  function init_signature_canvas(canvas, $wrapper) {
    const ctx = canvas.getContext("2d", { willReadFrequently: false, alpha: true });
    let strokes = [];
    let current_stroke = null;
    let is_drawing = false;
    let current_color = "#0f172a";

    // Color buttons listener
    $wrapper.find(".surhan-color-btn").on("click", function () {
      $wrapper.find(".surhan-color-btn").css("border", "2px solid transparent").removeClass("active");
      $(this).css("border", "2px solid #3b82f6").addClass("active");
      current_color = $(this).data("color") || "#0f172a";
      redraw();
    });

    function resize() {
      const rect = canvas.getBoundingClientRect();
      if (!rect.width || !rect.height) return;
      // Ultra-HD Super Sampling (at least 3x or 2x devicePixelRatio) for razor-sharp strokes
      const dpr = Math.max(window.devicePixelRatio || 1, 2);
      const scale = Math.max(dpr, 3);
      canvas.width = Math.floor(rect.width * scale);
      canvas.height = Math.floor(rect.height * scale);
      ctx.setTransform(scale, 0, 0, scale, 0, 0);
      ctx.imageSmoothingEnabled = true;
      ctx.imageSmoothingQuality = "high";
      redraw();
    }

    function point(e) {
      const rect = canvas.getBoundingClientRect();
      const p = (e.pressure && e.pressure > 0) ? Math.max(0.4, Math.min(e.pressure, 1.4)) : 0.8;
      return {
        x: +(e.clientX - rect.left).toFixed(2),
        y: +(e.clientY - rect.top).toFixed(2),
        p: p
      };
    }

    function redraw() {
      const rect = canvas.getBoundingClientRect();
      ctx.clearRect(0, 0, rect.width, rect.height);
      const pen_size = Number($wrapper.find("#surhan_canvas_pen").val() || 2.5);

      for (const stroke of strokes) {
        draw_stroke(stroke, pen_size, current_color);
      }
      if (current_stroke) {
        draw_stroke(current_stroke, pen_size, current_color);
      }
    }

    function draw_stroke(stroke, base_width, color) {
      if (!stroke || stroke.length < 2) return;
      ctx.save();
      ctx.lineCap = "round";
      ctx.lineJoin = "round";
      ctx.strokeStyle = color || current_color;
      ctx.lineWidth = base_width;

      ctx.beginPath();
      ctx.moveTo(stroke[0].x, stroke[0].y);

      for (let i = 1; i < stroke.length - 1; i++) {
        const mx = (stroke[i].x + stroke[i + 1].x) / 2;
        const my = (stroke[i].y + stroke[i + 1].y) / 2;
        ctx.quadraticCurveTo(stroke[i].x, stroke[i].y, mx, my);
      }

      const last = stroke[stroke.length - 1];
      ctx.lineTo(last.x, last.y);
      ctx.stroke();
      ctx.restore();
    }

    canvas.addEventListener("pointerdown", function (e) {
      e.preventDefault();
      try { canvas.setPointerCapture(e.pointerId); } catch (_) {}
      is_drawing = true;
      current_stroke = [point(e)];
    });

    canvas.addEventListener("pointermove", function (e) {
      if (!is_drawing || !current_stroke) return;
      e.preventDefault();
      current_stroke.push(point(e));
      redraw();
    });

    function end_stroke(e) {
      if (!is_drawing) return;
      is_drawing = false;
      try { canvas.releasePointerCapture(e.pointerId); } catch (_) {}
      if (current_stroke && current_stroke.length > 1) {
        strokes.push(current_stroke);
      }
      current_stroke = null;
      redraw();
    }

    canvas.addEventListener("pointerup", end_stroke);
    canvas.addEventListener("pointercancel", end_stroke);

    $wrapper.find("#btn_canvas_undo").on("click", function () {
      strokes.pop();
      redraw();
    });

    $wrapper.find("#btn_canvas_clear").on("click", function () {
      strokes = [];
      current_stroke = null;
      redraw();
    });

    $wrapper.find("#surhan_canvas_pen").on("input", function () {
      redraw();
    });

    resize();

    return {
      resize: resize,
      export_svg: function () {
        if (!strokes.length) return "";
        const rect = canvas.getBoundingClientRect();
        const width = Math.round(rect.width) || 600;
        const height = Math.round(rect.height) || 320;
        const pen_val = Number($wrapper.find("#surhan_canvas_pen").val() || 2.5);

        const paths = strokes.map(function (s) {
          if (!s || s.length < 2) return "";
          let d = "M " + s[0].x + " " + s[0].y;
          for (let i = 1; i < s.length - 1; i++) {
            const mx = ((s[i].x + s[i + 1].x) / 2).toFixed(1);
            const my = ((s[i].y + s[i + 1].y) / 2).toFixed(1);
            d += " Q " + s[i].x + " " + s[i].y + " " + mx + " " + my;
          }
          const last = s[s.length - 1];
          d += " L " + last.x + " " + last.y;
          return `<path d="${d}" fill="none" stroke="${current_color}" stroke-width="${pen_val}" stroke-linecap="round" stroke-linejoin="round"/>`;
        }).join("");

        return `<svg xmlns="http://www.w3.org/2000/svg" width="${width}" height="${height}" viewBox="0 0 ${width} ${height}"><rect width="100%" height="100%" fill="none"/>${paths}</svg>`;
      }
    };
  }

  function add_signature_buttons(frm, ctx) {
    if (!frm || !frm.page) return;

    const btn_label = __("✍️ توقيع / اعتماد المستند");

    // STRICT REQUIREMENT: If the document is completely signed, show NO buttons or menu options at all!
    if (ctx.complete) {
      if (frm.page.remove_inner_button) {
        frm.page.remove_inner_button(btn_label);
      }
      return;
    }

    // If the user has permission to sign (can_sign is true):
    if (ctx.can_sign) {
      if (frm.page.remove_inner_button) {
        frm.page.remove_inner_button(btn_label);
      }
      const btn = frm.add_custom_button(
        btn_label,
        function () {
          open_inpage_signature_dialog(frm, ctx);
        }
      );
      if (btn) {
        btn.addClass("btn-primary").css({
          "background-color": "#1b73e8",
          "border-color": "#1b73e8",
          "color": "#ffffff",
          "font-weight": "600",
          "box-shadow": "0 2px 4px rgba(27,115,232,0.3)"
        });
      }
    } else {
      if (frm.page.remove_inner_button) {
        frm.page.remove_inner_button(btn_label);
      }
    }
  }

  let form_context_inflight = false;
  async function load_form_context(frm) {
    if (!frm || !frm.doc || frm.is_new()) return;
    if (!has_ac_footer_field(frm)) return;
    if (form_context_inflight) return;
    form_context_inflight = true;

    try {
      // 100% Silent async call: never freezes the UI or interrupts document saving
      const r = await call_silent(
        "surhan_signature.api.get_document_signature_form_context",
        {
          reference_doctype: frm.doc.doctype,
          reference_name: frm.doc.name,
          auto_sync: 0
        }
      );

      const ctx = (r && r.message) ? r.message : r;
      if (!ctx || !ctx.ok) return;

      refresh_signature_indicator(frm, ctx);
      add_signature_buttons(frm, ctx);

      frm.__surhan_signature_context = ctx;
    } catch (e) {
      console.warn("Surhan Signature silent form check", e);
    } finally {
      form_context_inflight = false;
    }
  }

  // Hook 1: Direct Form Events via frappe.ui.form.on("*")
  if (frappe.ui && frappe.ui.form && frappe.ui.form.on) {
    try {
      frappe.ui.form.on("*", {
        refresh: function (frm) {
          load_form_context(frm);
        },
        after_save: function (frm) {
          load_form_context(frm);
        }
      });
    } catch (e) {
      console.warn("Surhan Signature form.on hook error", e);
    }
  }

  // Hook 2: Monkey-patch prototype refresh as a solid backup
  function patch_form_refresh() {
    if (!frappe.ui || !frappe.ui.form || !frappe.ui.form.Form) {
      setTimeout(patch_form_refresh, 300);
      return;
    }

    const proto = frappe.ui.form.Form.prototype;
    if (proto.__surhan_signature_refresh_patched) return;
    proto.__surhan_signature_refresh_patched = true;

    const original_refresh = proto.refresh;
    proto.refresh = function () {
      const result = original_refresh.apply(this, arguments);
      const frm = this;

      setTimeout(function () {
        load_form_context(frm);
      }, 150);

      return result;
    };
  }

  // Hook 3: Router & page changes
  if (frappe.router && frappe.router.on) {
    frappe.router.on("change", function () {
      setTimeout(function () {
        if (window.cur_frm) {
          load_form_context(window.cur_frm);
        }
      }, 200);
    });
  }

  $(document).on("page-change", function () {
    setTimeout(function () {
      if (window.cur_frm) {
        load_form_context(window.cur_frm);
      }
    }, 200);
  });

  // Initialization
  function init_runner() {
    patch_form_refresh();
    if (window.cur_frm) {
      load_form_context(window.cur_frm);
    }
  }

  if (typeof frappe.ready === "function") {
    frappe.ready(init_runner);
  } else if (typeof $ !== "undefined") {
    $(init_runner);
  } else {
    init_runner();
  }
})();
