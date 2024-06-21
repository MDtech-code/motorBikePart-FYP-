from django.db import models
from app.userprofile.models import CustomUser
# Create your models here.

class Product(models.Model):
    name=models.CharField(max_length=255)
    description=models.TextField(blank=True)
    price= models.DecimalField(max_digits=10,decimal_places=2)
    image=models.ImageField(upload_to='product_image/')
    stock=models.IntegerField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    def __str__(self):
        return self.name
    
class Cart(models.Model):
    user=models.ForeignKey(CustomUser,on_delete=models.CASCADE)
    created_at=models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Cart of {self.user.username}"
    
class CartItem(models.Model):
    cart=models.ForeignKey(Cart,on_delete=models.CASCADE)
    product=models.ForeignKey(Product,on_delete=models.CASCADE)
    quantity=models.PositiveIntegerField(default=1)
    created=models.DateTimeField(auto_now_add=True)
    updated=models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Cart Item - User: {self.cart.user.username}, Product: {self.product.name}, Quantity: {self.quantity}"


