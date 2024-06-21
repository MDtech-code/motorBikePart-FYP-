
from rest_framework import serializers
from .models import Product,Cart,CartItem



class ProductSerializer(serializers.ModelSerializer):
    class Meta:
        model=Product
        fields=['id','name','price','image','stock']

class ProductDetailSerializer(serializers.ModelSerializer):
    class Meta:
        model=Product
        fields=['id','name','description','price','image','stock']

class CartItemSerializer(serializers.ModelSerializer):
    product = serializers.PrimaryKeyRelatedField(queryset=Product.objects.all())
    class Meta:
        model= CartItem
        fields=['id','product','quantity']

class CartSerializer(serializers.ModelSerializer):
    items = CartItemSerializer(many=True, read_only=True)

    class Meta:
        model = Cart
        fields = ['id', 'user','items']