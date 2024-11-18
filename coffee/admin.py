from django.contrib import admin


from .models import Coffetable
from .models import Coffeproducts
from .models import Orders
from .models import History
from .models import Notification


admin.site.register(Coffetable)  
admin.site.register(Coffeproducts)
admin.site.register(Orders)
admin.site.register(History)
admin.site.register(Notification)

