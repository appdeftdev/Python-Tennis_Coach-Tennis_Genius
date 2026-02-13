from django.contrib import admin
from .models import Payment

@admin.register(Payment)
class PaymentAdmin(admin.ModelAdmin):
    list_display = ('id', 'platform', 'user', 'amount', 'currency', 'payment_type', 'transaction_id', 'status', 'created_at')
    list_filter = ('platform', 'status', 'currency', 'created_at')
    search_fields = ('transaction_id', 'user__email', 'user__username', 'product_id', 'original_transaction_id')
    ordering = ('-created_at',)
    readonly_fields = ('created_at', 'updated_at')
