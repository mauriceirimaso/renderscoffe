from django.db import models




class Coffetable(models.Model):
      
    email = models.EmailField(max_length=100, unique=True)  
    fullnames = models.CharField(max_length=100, null=True, blank=True)
    password = models.CharField(max_length=100, null=True, blank=True)
    profilephoto = models.CharField(max_length=255, default='profilephoto', null=True, blank=True)
    membership = models.CharField(max_length=100, blank=True)
    balance = models.FloatField(null=True, blank=True)
    


class Coffeproducts(models.Model):
      
    
    coffekind = models.CharField(max_length=100, null=True, blank=True)
    rating = models.FloatField( null=True, blank=True)
    coffename = models.CharField(max_length=100, blank=True)
    coffetype = models.CharField(max_length=100, blank=True)
    coffephoto = models.CharField(max_length=255, null=True, blank=True)
    price = models.FloatField(null=True, blank=True)
    descr = models.CharField(blank=True)
    ratingnumber = models.CharField( null=True, blank=True)

class Orders(models.Model):
      
    orderid = models.CharField( unique=True, blank=True)
    email = models.CharField(max_length=100, null=True, blank=True)
    productname = models.CharField( null=True, blank=True)
    producttype = models.CharField( null=True, blank=True)
    status = models.CharField(max_length=100, blank=True)
    quantity = models.IntegerField( blank=True,null=True)
    price = models.FloatField( null=True, blank=True)
    coffephoto = models.CharField(null=True, blank=True)
    time = models.CharField(max_length=100, blank=True)
    date = models.CharField(max_length=100, blank=True)
    isread = models.BooleanField(max_length=100, blank=True)
    
   
    


class History(models.Model):
      
    orderid = models.CharField(blank=True)
    email = models.CharField(max_length=100, null=True, blank=True)
    productname = models.CharField( null=True, blank=True)
    producttype = models.CharField( null=True, blank=True)
    status = models.CharField(max_length=100, blank=True)
    quantity = models.IntegerField( blank=True,null=True)
    price = models.FloatField( null=True, blank=True)
    coffephoto = models.CharField(null=True, blank=True)
    time = models.CharField(max_length=100, blank=True)
    date = models.CharField(max_length=100, blank=True)
    isread = models.BooleanField(max_length=100, blank=True)
    
   
    

class Notification(models.Model):
    notitype = models.CharField(blank=True)
    notiid = models.CharField(max_length=100, null=True, blank=True)
    email = models.CharField(max_length=100, null=True, blank=True)
    notiphoto = models.CharField( null=True, blank=True)
    date = models.CharField( null=True, blank=True)
    time = models.CharField( null=True, blank=True)
    balance = models.CharField( null=True, blank=True)
    isread = models.BooleanField( null=True, blank=True)
    

def __str__(self):
        return self.fullnames or self.email