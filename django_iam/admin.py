from django.contrib import admin

from .models import AuditLog, Policy, Principal, PrincipalRole, Role, RolePolicy


class RolePolicyInline(admin.TabularInline):
    model = RolePolicy
    extra = 0


class PrincipalRoleInline(admin.TabularInline):
    model = PrincipalRole
    extra = 0


@admin.register(Policy)
class PolicyAdmin(admin.ModelAdmin):
    list_display = ("name", "created_at", "updated_at")
    search_fields = ("name",)


@admin.register(Role)
class RoleAdmin(admin.ModelAdmin):
    list_display = ("name", "created_at", "updated_at")
    search_fields = ("name",)
    inlines = [RolePolicyInline]


@admin.register(Principal)
class PrincipalAdmin(admin.ModelAdmin):
    list_display = ("name", "principal_type", "user", "created_at", "updated_at")
    list_filter = ("principal_type",)
    search_fields = ("name", "user__username", "user__email")
    inlines = [PrincipalRoleInline]


@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    list_display = ("created_at", "principal", "action", "resource", "allowed", "reason")
    list_filter = ("allowed", "reason", "created_at")
    search_fields = ("principal__name", "user__username", "action", "resource")
    readonly_fields = (
        "principal",
        "user",
        "action",
        "resource",
        "context",
        "allowed",
        "reason",
        "matched_statements",
        "created_at",
    )

    def has_add_permission(self, request):
        return False
